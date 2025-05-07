// Debug flags
const DEBUG = {
    FORCE_DENY_MODE: false,      // Force deny mode regardless of usage
    FAKE_EGRESS_GB: 0,         // If > 0, simulate this many GB of egress usage (for testing)
    VERBOSE_LOGGING: true        // Enable additional logging
  };
  
  export default {
    // Handle fetch events (HTTP requests)
    async fetch(request, env, ctx) {
      // Only allow GET requests to /api/credentials/generate
      if (request.method !== "GET") {
        return new Response("Method not allowed", { status: 405 });
      }
      
      const url = new URL(request.url);
      if (url.pathname !== "/api/credentials/generate") {
        return new Response("Not found", { status: 404 });
      }
      
      try {
        // Check if we're in deny mode - using KV instead of global variable
        const denyModeStatus = await checkDenyMode(env);
        
        if (DEBUG.VERBOSE_LOGGING) {
          console.log(`Deny mode status: ${JSON.stringify(denyModeStatus)}`);
        }
        
        if (denyModeStatus.denied || DEBUG.FORCE_DENY_MODE) {
          return new Response(JSON.stringify({
            error: "Service temporarily unavailable - TURN egress limit exceeded",
            current_egress_gb: denyModeStatus.egressGB,
            limit_gb: Number(env.EGRESS_LIMIT || 700),
            last_revocation: denyModeStatus.lastRevocation
          }), {
            status: 503,
            headers: {
              "Content-Type": "application/json",
              "Retry-After": "3600" // Suggest retry after 1 hour
            }
          });
        }
        
        // Get client IP address
        const clientIP = request.headers.get("cf-connecting-ip");
        
        if (!clientIP) {
          throw new Error("Could not determine client IP");
        }
        
        // Apply rate limiting based on IP type
        let rateLimitKey = clientIP;
        let rateLimiterBinding;
        
        if (clientIP.includes(":")) {
          // IPv6 address - use /64 network prefix as the key
          const ipv6Prefix = clientIP.split(":").slice(0, 4).join(":");
          rateLimitKey = `${ipv6Prefix}::/64`;
          rateLimiterBinding = env.IPV6_CREDENTIAL_GENERATE_RATE_LIMITER;
        } else {
          // IPv4 address - use the full address
          rateLimiterBinding = env.IPV4_CREDENTIAL_GENERATE_RATE_LIMITER;
        }
        
        // Apply rate limiting
        if (rateLimiterBinding) {
          const rateLimitResult = await rateLimiterBinding.limit({
            key: rateLimitKey
          });
          
          if (!rateLimitResult.success) {
            // Handle reset time safely
            let resetTime;
            try {
              // The reset value might be a timestamp in milliseconds
              resetTime = new Date(rateLimitResult.reset).toISOString();
            } catch (e) {
              // If there's an error parsing the date, just use the raw value
              resetTime = rateLimitResult.reset;
            }
            
            // Calculate retry-after in seconds (with fallback)
            let retryAfter = 60; // Default fallback
            if (typeof rateLimitResult.reset === 'number') {
              const now = Date.now();
              if (rateLimitResult.reset > now) {
                retryAfter = Math.ceil((rateLimitResult.reset - now) / 1000);
              }
            }
            
            return new Response(
              JSON.stringify({
                error: "Rate limit exceeded",
                limit: rateLimitResult.limit,
                reset: resetTime
              }),
              {
                status: 429,
                headers: {
                  "Content-Type": "application/json",
                  "Retry-After": String(retryAfter)
                }
              }
            );
          }
        }
        
        // Generate ICE credentials
        const credentials = await generateIceCredentials(env);
        
        // Store the username in KV
        await storeUsername(credentials.username, env);
        
        // Return the credentials
        return new Response(JSON.stringify({
          username: credentials.username,
          credential: credentials.credential,
          ttl: Number(env.CREDENTIAL_TTL || 86400)
        }), {
          headers: {
            "Content-Type": "application/json"
          }
        });
      } catch (error) {
        console.error("Error:", error);
        return new Response(JSON.stringify({ error: error.message }), {
          status: 500,
          headers: {
            "Content-Type": "application/json"
          }
        });
      }
    },
    
    // Handle scheduled events (cron jobs)
    async scheduled(event, env, ctx) {
      const currentTime = new Date().toISOString();
      console.log(`Scheduled egress check at: ${currentTime}`);
      
      try {
        await checkTurnEgressUsage(env);
      } catch (error) {
        console.error(`Scheduled job error: ${error.message}`);
      }
    }
  };
  
  /**
   * Check if the service is in deny mode by reading from KV
   * @param {Object} env - Environment variables
   * @returns {Object} - Deny mode status object
   */
  async function checkDenyMode(env) {
    try {
      // Get the last revocation info from KV
      const lastRevocationData = await env.KV.get('last_revocation', { type: 'json' });
      
      if (!lastRevocationData) {
        return {
          denied: false,
          egressGB: 0,
          lastRevocation: null
        };
      }
      
      // Check if we're still in deny mode
      const { timestamp, egressBytes, limitBytes } = lastRevocationData;
      const revocationTime = new Date(timestamp);
      const currentTime = new Date();
      
      // Calculate if we're still in deny mode - resets at start of new month
      const stillDenied = revocationTime.getUTCMonth() === currentTime.getUTCMonth() && 
                         revocationTime.getUTCFullYear() === currentTime.getUTCFullYear() &&
                         egressBytes > limitBytes;
      
      // Convert bytes to GB for display
      const egressGB = Math.round(egressBytes / (1024 * 1024 * 1024) * 100) / 100;
      
      return {
        denied: stillDenied,
        egressGB,
        lastRevocation: timestamp
      };
    } catch (error) {
      console.error("Error checking deny mode:", error);
      return {
        denied: false,
        egressGB: 0,
        lastRevocation: null
      };
    }
  }
  
  /**
   * Check TURN egress usage and take action if limit is exceeded
   * @param {Object} env - Environment variables
   */
  async function checkTurnEgressUsage(env) {
    console.log("Starting TURN egress usage check");
    
    const analyticsToken = env.ANALYTICS_TOKEN;
    const turnKeyId = env.TURN_KEY_ID;
    const accountTag = env.ACCOUNT_TAG;
    const egressLimit = Number(env.EGRESS_LIMIT || 700) * 1024 * 1024 * 1024; // Convert GB to bytes
    
    if (!analyticsToken || !turnKeyId) {
      throw new Error("Missing ANALYTICS_TOKEN or TURN_KEY_ID environment variables");
    }
    
    // Get date range for current month
    const now = new Date();
    const firstDay = new Date(now.getFullYear(), now.getMonth(), 1);
    const startDate = firstDay.toISOString();
    const endDate = now.toISOString();
    
    console.log(`Checking usage from ${startDate} to ${endDate}`);
    
    // Check if we should use fake egress data
    let egressBytes;
    if (DEBUG.FAKE_EGRESS_GB > 0) {
      egressBytes = DEBUG.FAKE_EGRESS_GB * 1024 * 1024 * 1024; // Convert GB to bytes
      console.log(`DEBUG: Using fake egress data: ${DEBUG.FAKE_EGRESS_GB} GB (${egressBytes} bytes)`);
    } else {
      // Build GraphQL query
      let queryText;
      
      if (accountTag) {
        // If we have an account tag, use it
        queryText = `
          query {
            viewer {
              accounts(filter: {accountTag: "${accountTag}"}) {
                callsTurnUsageAdaptiveGroups(
                  filter: {
                    datetimeMinute_gt: "${startDate}"
                    datetimeMinute_lt: "${endDate}"
                    keyId: "${turnKeyId}"
                  }
                  limit: 1
                  orderBy: [sum_egressBytes_DESC]
                ) {
                  sum {
                    egressBytes
                  }
                }
              }
            }
          }
        `;
      } else {
        // Otherwise just use an empty object for the filter
        queryText = `
          query {
            viewer {
              accounts(filter: {}) {
                callsTurnUsageAdaptiveGroups(
                  filter: {
                    datetimeMinute_gt: "${startDate}"
                    datetimeMinute_lt: "${endDate}"
                    keyId: "${turnKeyId}"
                  }
                  limit: 1
                  orderBy: [sum_egressBytes_DESC]
                ) {
                  sum {
                    egressBytes
                  }
                }
              }
            }
          }
        `;
      }
      
      // Make the GraphQL request
      const response = await fetch("https://api.cloudflare.com/client/v4/graphql", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${analyticsToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ query: queryText })
      });
      
      // Check for HTTP errors
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP error ${response.status}: ${errorText}`);
      }
      
      // Parse response
      const result = await response.json();
      
      // Check for GraphQL errors
      if (result.errors && result.errors.length > 0) {
        throw new Error(`GraphQL errors: ${JSON.stringify(result.errors)}`);
      }
      
      // Extract egress bytes from the result
      egressBytes = extractEgressBytes(result);
    }
    
    // Convert to GB for easier reading
    const egressGB = Math.round(egressBytes / (1024 * 1024 * 1024) * 100) / 100;
    const limitGB = Number(env.EGRESS_LIMIT || 700);
    
    console.log(`Current TURN egress usage: ${egressGB} GB of ${limitGB} GB limit`);
    
    // Check if we've exceeded the limit
    if (egressBytes > egressLimit) {
      console.log("EGRESS LIMIT EXCEEDED - Enabling deny mode and revoking credentials");
      await setDenyMode(env, egressBytes, egressLimit);
      await revokeAllCredentials(env);
    } else {
      // Check if we were previously in deny mode
      const denyModeStatus = await checkDenyMode(env);
      if (denyModeStatus.denied) {
        console.log("Usage now under limit - Clearing deny mode");
        await clearDenyMode(env);
      }
    }
  }
  
  /**
   * Set deny mode in KV storage
   * @param {Object} env - Environment variables
   * @param {number} egressBytes - Current egress usage in bytes
   * @param {number} limitBytes - Egress limit in bytes
   */
  async function setDenyMode(env, egressBytes, limitBytes) {
    const timestamp = new Date().toISOString();
    
    const revocationData = {
      timestamp,
      egressBytes,
      limitBytes
    };
    
    await env.KV.put('last_revocation', JSON.stringify(revocationData));
    console.log(`Deny mode set at ${timestamp} - usage: ${egressBytes} bytes, limit: ${limitBytes} bytes`);
  }
  
  /**
   * Clear deny mode in KV storage
   * @param {Object} env - Environment variables
   */
  async function clearDenyMode(env) {
    // We don't delete the key, but update it to mark the service as no longer in deny mode
    const currentData = await env.KV.get('last_revocation', { type: 'json' }) || {};
    
    const updatedData = {
      ...currentData,
      egressBytes: 0, // Set to 0 to ensure it's below the limit
      timestamp: new Date().toISOString()
    };
    
    await env.KV.put('last_revocation', JSON.stringify(updatedData));
    console.log("Deny mode cleared");
  }
  
  /**
   * Helper function to extract egress bytes from GraphQL response
   * @param {Object} data - GraphQL response data
   * @returns {number} - Egress bytes value
   */
  function extractEgressBytes(data) {
    try {
      // Navigate through the response structure
      const accounts = data?.data?.viewer?.accounts || [];
      if (DEBUG.VERBOSE_LOGGING) {
        console.log(`Found ${accounts.length} accounts`);
      }
      
      if (accounts.length === 0) {
        return 0;
      }
      
      const usageGroups = accounts[0]?.callsTurnUsageAdaptiveGroups || [];
      if (DEBUG.VERBOSE_LOGGING) {
        console.log(`Found ${usageGroups.length} usage groups`);
      }
      
      if (usageGroups.length === 0) {
        return 0;
      }
      
      return usageGroups[0]?.sum?.egressBytes || 0;
    } catch (error) {
      console.error("Error extracting egress bytes:", error);
      return 0;
    }
  }
  
  /**
   * Revokes all stored credentials and clears storage
   * @param {Object} env - Environment variables
   */
  async function revokeAllCredentials(env) {
    try {
      const usernamesObj = await env.KV.get("username", { type: "json" }) || { username: [] };
      
      console.log(`Revoking ${usernamesObj.username.length} credentials`);
      
      for (const username of usernamesObj.username) {
        try {
          await revokeCredential(username, env);
          console.log(`Successfully revoked credential for ${username}`);
        } catch (error) {
          console.error(`Failed to revoke ${username}: ${error.message}`);
        }
      }
      
      await env.KV.put("username", JSON.stringify({ username: [] }));
      console.log("Cleared username storage");
      
    } catch (error) {
      console.error(`Error in revokeAllCredentials: ${error.message}`);
    }
  }
  
  /**
   * Revokes a TURN credential
   * @param {string} username - The username to revoke
   * @param {Object} env - Environment variables
   */
  async function revokeCredential(username, env) {
    const turnKeyId = env.TURN_KEY_ID;
    const turnKeySecret = env.TURN_KEY_SECRET;
    
    if (!turnKeyId || !turnKeySecret || !username) {
      throw new Error("Missing required parameters for credential revocation");
    }
    
    try {
      const response = await fetch(
        `https://rtc.live.cloudflare.com/v1/turn/keys/${turnKeyId}/credentials/${username}/revoke`,
        {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${turnKeySecret}`
          }
        }
      );
      
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`API error ${response.status}: ${errorText}`);
      }
      
      // Handle empty responses gracefully
      const contentType = response.headers.get("content-type");
      if (contentType && contentType.includes("application/json")) {
        try {
          return await response.json();
        } catch (jsonError) {
          console.log(`Response was not valid JSON, but revocation was successful for ${username}`);
          return { success: true };
        }
      } else {
        console.log(`Non-JSON response (${response.status}), but revocation was successful for ${username}`);
        return { success: true };
      }
    } catch (error) {
      console.error(`Network error during revocation: ${error.message}`);
      throw error;
    }
  }
  
  /**
   * Generates ICE server credentials by calling Cloudflare TURN API
   * @param {Object} env - Environment variables
   * @returns {Object} Object containing username and credential
   */
  async function generateIceCredentials(env) {
    const turnKeyId = env.TURN_KEY_ID;
    const turnKeySecret = env.TURN_KEY_SECRET;
    const credentialTtl = Number(env.CREDENTIAL_TTL || 86400);
    
    if (!turnKeyId || !turnKeySecret) {
      throw new Error("TURN credentials not configured");
    }
    
    // Ensure the TTL is a number, not a string
    const ttlValue = Number.isNaN(credentialTtl) ? 86400 : credentialTtl;
    
    // Create the request body as a stringified JSON object
    const requestBody = JSON.stringify({ ttl: ttlValue });
    
    const response = await fetch(
      `https://rtc.live.cloudflare.com/v1/turn/keys/${turnKeyId}/credentials/generate-ice-servers`,
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${turnKeySecret}`,
          "Content-Type": "application/json"
        },
        body: requestBody
      }
    );
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error("API Error Response:", errorText);
      throw new Error(`Failed to generate credentials: ${errorText}`);
    }
    
    const data = await response.json();
    
    // Extract the username and credential from the response
    const turnServer = data.iceServers.find(server => server.credential && server.username);
    
    if (!turnServer) {
      throw new Error("Could not find TURN server with credentials in response");
    }
    
    return {
      username: turnServer.username,
      credential: turnServer.credential
    };
  }
  
  /**
   * Stores the generated username in KV storage
   * @param {string} username - The username to store
   * @param {Object} env - Environment variables
   */
  async function storeUsername(username, env) {
    if (!env.KV) {
      throw new Error("KV namespace not bound to worker");
    }
    
    // Get existing usernames
    let usernamesObj;
    try {
      usernamesObj = await env.KV.get("username", { type: "json" });
      usernamesObj = usernamesObj || { username: [] };
    } catch (error) {
      // If no usernames exist or there was an error parsing JSON
      console.error("KV error:", error);
      usernamesObj = { username: [] };
    }
    
    // Add the new username if it doesn't already exist
    if (!usernamesObj.username.includes(username)) {
      usernamesObj.username.push(username);
      
      // Store the updated usernames object
      await env.KV.put("username", JSON.stringify(usernamesObj));
    }
  }