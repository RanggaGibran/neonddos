package id.neonddos;

import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.scheduler.BukkitRunnable;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;

/**
 * Sistem yang mengatur prioritas traffic jaringan dan mengalokasikan sumber daya
 * berdasarkan reputasi, status, dan jenis koneksi
 */
public class TrafficPrioritizer {
    
    private final neonddos plugin;
    private final Logger logger;
    
    // Traffic prioritization settings
    private boolean enableTrafficPrioritization;
    private boolean enableDynamicBandwidthAllocation;
    private int maxLowPriorityRequestsPerSecond;
    private int maxTotalConnectionsPerSec;
    
    // Traffic rate tracking
    private final Map<String, TrafficInfo> trafficRates = new ConcurrentHashMap<>();
    private final Map<String, Integer> connectionRates = new ConcurrentHashMap<>();
    
    // Maps player UUID to IP address for priority management
    private final Map<String, UUID> ipToPlayerMap = new ConcurrentHashMap<>();
    
    // Current load level (0-100%)
    private int currentServerLoad = 0;
    
    // Priority thresholds for limiting connections
    private static final int MAX_PRIORITY = 10;
    private static final int PLAYER_BASE_PRIORITY = 8;
    private static final int ADMIN_PRIORITY = 10;
    
    public TrafficPrioritizer(neonddos plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        
        // Load configuration
        loadConfiguration();
        
        // Start monitoring tasks
        startMonitoringTasks();
        
        // Start player tracking
        trackActivePlayers();
        
        logger.info("Traffic Prioritizer diinisialisasi - Traffic prioritization: " + 
                   (enableTrafficPrioritization ? "enabled" : "disabled"));
    }
    
    /**
     * Load configuration from config.yml
     */
    private void loadConfiguration() {
        FileConfiguration config = plugin.getConfig();
        
        enableTrafficPrioritization = config.getBoolean("traffic-prioritization.enabled", true);
        enableDynamicBandwidthAllocation = config.getBoolean("traffic-prioritization.dynamicBandwidthAllocation", true);
        maxLowPriorityRequestsPerSecond = config.getInt("traffic-prioritization.maxLowPriorityRequestsPerSecond", 20);
        maxTotalConnectionsPerSec = config.getInt("traffic-prioritization.maxConnectionsPerSecond", 100);
        
        logger.info("Traffic prioritization configuration loaded with max low priority requests: " + 
                   maxLowPriorityRequestsPerSecond);
    }
    
    /**
     * Start monitoring tasks for traffic prioritization
     */
    private void startMonitoringTasks() {
        // Reset connection rates every second
        new BukkitRunnable() {
            @Override
            public void run() {
                connectionRates.clear();
                
                // Update server load
                updateServerLoad();
            }
        }.runTaskTimerAsynchronously(plugin, 20L, 20L); // Every 1 second
        
        // Cleanup old traffic data
        new BukkitRunnable() {
            @Override
            public void run() {
                long now = System.currentTimeMillis();
                trafficRates.entrySet().removeIf(entry -> 
                    now - entry.getValue().lastUpdated > 300000); // 5 minutes
            }
        }.runTaskTimerAsynchronously(plugin, 20L * 60, 20L * 60); // Every 1 minute
    }
    
    /**
     * Track player join/quit to maintain priority
     */
    private void trackActivePlayers() {
        // Initially add all online players
        for (Player player : Bukkit.getOnlinePlayers()) {
            if (player.getAddress() != null) {
                String ip = player.getAddress().getAddress().getHostAddress();
                ipToPlayerMap.put(ip, player.getUniqueId());
            }
        }
        
        // Register event handlers for join/quit through the plugin class
    }
    
    /**
     * Handle player join event to track IP for prioritization
     */
    public void handlePlayerJoin(String ip, UUID playerUUID) {
        ipToPlayerMap.put(ip, playerUUID);
    }
    
    /**
     * Handle player quit event to update IP tracking
     */
    public void handlePlayerQuit(String ip) {
        // Don't immediately remove as the player might reconnect
        // Instead, we'll rely on the cleanup task
    }
    
    /**
     * Calculate current server load based on TPS and connections
     */
    private void updateServerLoad() {
        // Get TPS (Ticks Per Second) as a measure of server performance
        double tps = getTPS();
        
        // Calculate load percentage: 20 TPS = 0% load, 10 TPS = 50% load, 0 TPS = 100% load
        int tpsLoad = (int)((20.0 - Math.min(tps, 20.0)) * 5);
        
        // Factor in connection count
        int connectionCount = connectionRates.size();
        int connectionLoad = Math.min(connectionCount * 100 / maxTotalConnectionsPerSec, 100);
        
        // Combined load (weighted average)
        currentServerLoad = (tpsLoad * 70 + connectionLoad * 30) / 100;
        
        // Log load level changes for monitoring
        if (currentServerLoad > 80) {
            logger.warning("High server load detected: " + currentServerLoad + "% - Increasing traffic restrictions");
        }
    }
    
    /**
     * Get current server TPS (Ticks Per Second)
     */
    private double getTPS() {
        try {
            // Try to access Spigot's TPS reporting
            Object serverObj = Bukkit.getServer();
            java.lang.reflect.Method getServerMethod = serverObj.getClass().getMethod("getServer");
            Object server = getServerMethod.invoke(serverObj);
            java.lang.reflect.Field recentTpsField = server.getClass().getField("recentTps");
            double[] tps = (double[]) recentTpsField.get(server);
            
            // Return the 1-minute TPS average
            return tps[0];
        } catch (Exception e) {
            // Fallback if we can't access TPS
            return 20.0; // Assume perfect TPS if can't measure
        }
    }
    
    /**
     * Process an incoming connection and determine if it should be accepted
     * based on traffic prioritization rules
     * 
     * @param address The IP address of the connection
     * @param connectionType The type of connection
     * @return true if connection should be accepted, false if throttled/rejected
     */
    public boolean processConnection(InetAddress address, ConnectionType connectionType) {
        if (!enableTrafficPrioritization) {
            return true; // Traffic prioritization disabled, accept all connections
        }
        
        String ip = address.getHostAddress();
        
        // Track connection rate
        connectionRates.compute(ip, (k, v) -> v == null ? 1 : v + 1);
        
        // Get connection priority
        int priority = determineConnectionPriority(ip, connectionType);
        
        // Update traffic information
        TrafficInfo trafficInfo = trafficRates.computeIfAbsent(ip, k -> new TrafficInfo());
        trafficInfo.connectionCount++;
        trafficInfo.lastUpdated = System.currentTimeMillis();
        
        // Under high load, enforce stricter prioritization
        if (currentServerLoad > 70) {
            // Calculate threshold based on priority and server load
            int requestThreshold = calculateRequestThreshold(priority);
            
            // Check if this IP has exceeded its threshold
            if (connectionRates.getOrDefault(ip, 0) > requestThreshold) {
                // Connection rejected due to prioritization under high load
                logger.fine("Connection throttled: " + ip + " (priority " + priority + 
                          ", rate " + connectionRates.get(ip) + " > threshold " + requestThreshold + ")");
                return false;
            }
        }
        
        // For low priority connections, always apply rate limiting
        if (priority < 5) {
            if (connectionRates.getOrDefault(ip, 0) > maxLowPriorityRequestsPerSecond) {
                // Low priority connection exceeding rate limit
                logger.fine("Low priority connection throttled: " + ip);
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Determine the priority of a connection (0-10 scale)
     * Higher values = higher priority
     */
    private int determineConnectionPriority(String ip, ConnectionType connectionType) {
        int priority = 0;
        
        // Check if this is a player's IP
        if (ipToPlayerMap.containsKey(ip)) {
            UUID playerUUID = ipToPlayerMap.get(ip);
            Player player = Bukkit.getPlayer(playerUUID);
            
            if (player != null) {
                // Active player gets high priority
                priority = PLAYER_BASE_PRIORITY;
                
                // Admin gets highest priority
                if (player.isOp() || player.hasPermission("neonddos.admin")) {
                    priority = ADMIN_PRIORITY;
                }
            } else {
                // Recent player but not currently online
                priority = 6;
            }
        }
        
        // Check connection type
        switch (connectionType) {
            case PLAYER_JOIN:
            case PLAYER_LOGIN:
                // Boost priority for actual login attempts
                priority = Math.max(priority, 7);
                break;
                
            case SERVER_PING:
                // Server list pings get lower priority
                if (priority <= 0) { // If not a known player's ping
                    priority = 3;
                }
                break;
        }
        
        // Check IP reputation if available
        AnalyticsSystem analyticsSystem = plugin.getAnalyticsSystem();
        if (analyticsSystem != null) {
            AnalyticsSystem.IpReputation reputation = analyticsSystem.getIpReputation(ip);
            
            // Adjust based on reputation score (-100 to 100)
            if (reputation.getReputationScore() < -50) {
                // Bad reputation
                priority = Math.max(0, priority - 3);
            } else if (reputation.getReputationScore() > 50) {
                // Good reputation
                priority = Math.min(MAX_PRIORITY, priority + 1);
            }
        }
        
        return Math.max(0, Math.min(priority, MAX_PRIORITY));
    }
    
    /**
     * Calculate request threshold based on priority and server load
     */
    private int calculateRequestThreshold(int priority) {
        // Base threshold from configuration
        int baseThreshold = maxLowPriorityRequestsPerSecond;
        
        // Calculate dynamic threshold based on priority
        // Higher priority = higher threshold
        double priorityFactor = 1.0 + (priority * 0.3); // 0 = 1x, 10 = 4x
        
        // Apply server load factor - reduce threshold under high load
        double loadFactor = Math.max(0.1, 1.0 - (currentServerLoad / 100.0));
        
        return (int)(baseThreshold * priorityFactor * loadFactor);
    }
    
    /**
     * Allocate bandwidth dynamically between connections
     * @param ip The IP address requesting bandwidth
     * @param requestedAmount The amount of bandwidth requested
     * @return The allocated bandwidth amount
     */
    public int allocateBandwidth(String ip, int requestedAmount) {
        if (!enableDynamicBandwidthAllocation) {
            return requestedAmount; // No dynamic allocation, return requested amount
        }
        
        // Get connection priority
        int priority = determineConnectionPriority(ip, null);
        
        // Base allocation percentage based on priority
        double allocationFactor = 0.5 + (priority * 0.05); // 50% to 100%
        
        // Under high load, reduce allocation more heavily for low-priority connections
        if (currentServerLoad > 50) {
            double loadAdjustment = (currentServerLoad - 50) / 100.0;
            allocationFactor = allocationFactor * (1.0 - loadAdjustment * (MAX_PRIORITY - priority) / MAX_PRIORITY);
        }
        
        // Ensure at least 10% minimum allocation
        allocationFactor = Math.max(0.1, allocationFactor);
        
        // Calculate allocated bandwidth
        int allocatedAmount = (int)(requestedAmount * allocationFactor);
        
        return allocatedAmount;
    }
    
    /**
     * Get the current server load (0-100%)
     */
    public int getCurrentServerLoad() {
        return currentServerLoad;
    }
    
    /**
     * Enable or disable traffic prioritization
     */
    public void setTrafficPrioritizationEnabled(boolean enabled) {
        this.enableTrafficPrioritization = enabled;
    }
    
    /**
     * Enable or disable dynamic bandwidth allocation
     */
    public void setDynamicBandwidthAllocationEnabled(boolean enabled) {
        this.enableDynamicBandwidthAllocation = enabled;
    }
    
    /**
     * Set max low priority requests per second
     */
    public void setMaxLowPriorityRequestsPerSecond(int max) {
        this.maxLowPriorityRequestsPerSecond = max;
    }
    
    /**
     * Get traffic statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("enabled", enableTrafficPrioritization);
        stats.put("dynamicBandwidthEnabled", enableDynamicBandwidthAllocation);
        stats.put("currentServerLoad", currentServerLoad);
        stats.put("trackingIpsCount", trafficRates.size());
        stats.put("knownPlayersCount", ipToPlayerMap.size());
        stats.put("maxLowPriorityRPS", maxLowPriorityRequestsPerSecond);
        
        return stats;
    }
    
    /**
     * Connection type enum
     */
    public enum ConnectionType {
        SERVER_PING,
        PLAYER_LOGIN,
        PLAYER_JOIN,
        RESOURCE_REQUEST
    }
    
    /**
     * Class to track traffic information for an IP
     */
    private static class TrafficInfo {
        int connectionCount = 0;
        long lastUpdated = System.currentTimeMillis();
    }
}