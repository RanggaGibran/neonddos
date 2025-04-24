package id.neonddos;

import org.bukkit.Bukkit;
import org.bukkit.configuration.file.FileConfiguration;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Kelas untuk deteksi serangan DDoS yang lebih canggih
 * dengan berbagai algoritma dan metrik
 */
public class DdosDetector {

    private final neonddos plugin;
    private final Logger logger;
    private final ConnectionMonitor connectionMonitor;
    
    // Data untuk analisis
    private final Map<String, List<ConnectionData>> connectionData;
    private final Map<String, AttackReport> attackReports;
    
    // Konfigurasi
    private int packetRateThreshold = 100;         // Paket per detik
    private int connectionBurstThreshold = 5;      // Koneksi dalam 1 detik
    private int connectionPatternThreshold = 10;   // Pola koneksi mencurigakan
    private int totalAttackScoreThreshold = 100;   // Skor untuk trigger alert
    private long analysisInterval = 30000;         // Interval analisis (30 detik)
    
    // Statistik
    private int detectedAttacks = 0;
    private final List<String> blockedIps = new ArrayList<>();
    
    public DdosDetector(neonddos plugin, ConnectionMonitor connectionMonitor) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.connectionMonitor = connectionMonitor;
        this.connectionData = new ConcurrentHashMap<>();
        this.attackReports = new ConcurrentHashMap<>();
        
        // Load konfigurasi
        loadConfiguration();
        
        // Mulai monitoring
        startMonitoring();
        
        logger.info("Sistem deteksi DDoS canggih telah diinisialisasi");
    }
    
    /**
     * Load konfigurasi dari config.yml
     */
    public void loadConfiguration() {
        FileConfiguration config = plugin.getConfig();
        
        packetRateThreshold = config.getInt("detection.packetRateThreshold", 100);
        connectionBurstThreshold = config.getInt("detection.connectionBurstThreshold", 5);
        connectionPatternThreshold = config.getInt("detection.connectionPatternThreshold", 10);
        totalAttackScoreThreshold = config.getInt("detection.totalAttackScoreThreshold", 100);
        analysisInterval = config.getLong("detection.analysisInterval", 30000);
        
        logger.info("Konfigurasi deteksi DDoS dimuat: " +
                    "packetRate=" + packetRateThreshold + ", " +
                    "connectionBurst=" + connectionBurstThreshold + ", " +
                    "patternThreshold=" + connectionPatternThreshold);
    }
    
    /**
     * Mulai task monitoring serangan DDoS
     */
    private void startMonitoring() {
        // Task untuk analisis data dan deteksi serangan
        Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, this::analyzeConnectionData, 
            20L, 20L * (analysisInterval / 1000)); 
        
        logger.info("Monitoring serangan DDoS aktif dengan interval " + (analysisInterval / 1000) + " detik");
    }
    
    /**
     * Mencatat koneksi untuk analisis
     */
    public void recordConnection(InetAddress address, int packetSize, ConnectionType type) {
        String ip = address.getHostAddress();
        long timestamp = System.currentTimeMillis();
        
        // Simpan data koneksi
        ConnectionData data = new ConnectionData(timestamp, packetSize, type);
        connectionData.computeIfAbsent(ip, k -> new ArrayList<>()).add(data);
        
        // Analisis cepat untuk deteksi serangan burst
        detectConnectionBurst(ip);
    }
    
    /**
     * Deteksi koneksi burst (banyak koneksi dalam waktu singkat)
     */
    private void detectConnectionBurst(String ip) {
        List<ConnectionData> connections = connectionData.get(ip);
        if (connections == null || connections.size() < connectionBurstThreshold) {
            return;
        }
        
        // Hitung jumlah koneksi dalam 1 detik terakhir
        long now = System.currentTimeMillis();
        long oneSecondAgo = now - 1000;
        
        long recentConnections = connections.stream()
            .filter(c -> c.timestamp > oneSecondAgo)
            .count();
            
        if (recentConnections >= connectionBurstThreshold) {
            int score = (int)(recentConnections * 2);
            reportSuspiciousActivity(ip, "Koneksi burst", score);
        }
    }
    
    /**
     * Analisis mendalam terhadap data koneksi
     */
    private void analyzeConnectionData() {
        long now = System.currentTimeMillis();
        
        // Iterasi tiap IP
        for (Map.Entry<String, List<ConnectionData>> entry : connectionData.entrySet()) {
            String ip = entry.getKey();
            List<ConnectionData> connections = entry.getValue();
            
            // Hanya analisis data dalam jendela waktu tertentu
            connections.removeIf(c -> (now - c.timestamp) > analysisInterval);
            
            // Jika tidak ada data, skip
            if (connections.isEmpty()) {
                connectionData.remove(ip);
                continue;
            }
            
            // Kalkulasi metrik-metrik untuk deteksi
            int totalScore = 0;
            
            // 1. Check packet rate
            double packetsPerSecond = calculatePacketRate(connections, now);
            if (packetsPerSecond > packetRateThreshold) {
                int score = (int)(packetsPerSecond / packetRateThreshold * 50);
                totalScore += score;
                reportSuspiciousActivity(ip, "Packet flooding", score);
            }
            
            // 2. Deteksi pola koneksi mencurigakan
            int patternScore = detectSuspiciousPatterns(connections);
            if (patternScore > 0) {
                totalScore += patternScore;
                reportSuspiciousActivity(ip, "Pola koneksi mencurigakan", patternScore);
            }
            
            // 3. Cek jenis koneksi (lebih banyak ping daripada join)
            int connectionTypeScore = analyzeConnectionTypes(connections);
            if (connectionTypeScore > 0) {
                totalScore += connectionTypeScore;
                reportSuspiciousActivity(ip, "Rasio ping/join abnormal", connectionTypeScore);
            }
            
            // Gunakan MLEngine untuk meningkatkan deteksi
            MLEngine mlEngine = plugin.getMLEngine();
            if (mlEngine != null) {
                // Buat ConnectionData dari data koneksi yang tersedia
                final MLEngine.ConnectionData connectionData = createConnectionDataForML(ip);
                
                // Dapatkan skor ML
                double mlScore = mlEngine.checkConnection(ip, connectionData);
                
                // Tambahkan skor ML ke total (dikali 100 untuk skala yang sama)
                if (mlScore > 0.5) { // only add if significant
                    int mlScoreInt = (int)(mlScore * 100);
                    totalScore += mlScoreInt;
                    
                    // Tambahkan deteksi ML ke report
                    AttackReport report = attackReports.computeIfAbsent(ip, k -> new AttackReport());
                    report.addDetection("ML_DETECTION", mlScoreInt);
                    
                    logger.fine("ML detection untuk " + ip + ": " + mlScore + 
                              " (+" + mlScoreInt + " ke total skor)");
                }
            }
            
            // Evaluasi total skor
            if (totalScore >= totalAttackScoreThreshold) {
                handleAttackDetection(ip, totalScore);
            }
        }
        
        // Bersihkan laporan serangan lama
        cleanupAttackReports(now);
        
        // Trim data koneksi yang terlalu lama
        trimConnectionData();
    }
    
    /**
     * Create ConnectionData object for ML analysis
     */
    private MLEngine.ConnectionData createConnectionDataForML(String ip) {
        // Extract metrics from connection history
        List<ConnectionData> records = connectionData.getOrDefault(ip, new ArrayList<>());
        
        int connectionCount = records.size();
        double avgInterval = 1000.0; // default 1 second
        double stdDev = 0.0;
        double maxRate = 0.0;
        int burstCount = 0;
        double synRatio = 0.5; // default half
        double completionRatio = 1.0; // default all complete
        double userAgentVariety = 0.0;
        
        if (connectionCount > 1) {
            // Calculate intervals
            List<Long> intervals = new ArrayList<>();
            for (int i = 1; i < records.size(); i++) {
                intervals.add(records.get(i).timestamp - records.get(i-1).timestamp);
            }
            
            // Calculate average interval
            long totalInterval = intervals.stream().mapToLong(Long::longValue).sum();
            // Create a new variable instead of modifying avgInterval since it's used in a lambda below
            double calculatedAvgInterval = (double) totalInterval / intervals.size();
            
            // Use calculatedAvgInterval in standard deviation calculation
            double variance = intervals.stream()
                .mapToDouble(interval -> Math.pow(interval - calculatedAvgInterval, 2))
                .sum() / intervals.size();
            stdDev = Math.sqrt(variance);
            
            // Calculate max connections per second
            Map<Long, Integer> connectionsPerSecond = new HashMap<>();
            for (ConnectionData record : records) {
                long second = record.timestamp / 1000;
                connectionsPerSecond.put(second, connectionsPerSecond.getOrDefault(second, 0) + 1);
            }
            maxRate = connectionsPerSecond.values().stream()
                .mapToInt(Integer::intValue)
                .max()
                .orElse(0);
            
            // Count bursts (>5 connections per second)
            burstCount = (int) connectionsPerSecond.values().stream()
                .filter(count -> count >= 5)
                .count();
            
            // Extract other metrics if available
            synRatio = records.stream()
                .filter(r -> r.type == ConnectionType.SERVER_PING)
                .count() / (double) records.size();
            
            completionRatio = records.stream()
                .filter(r -> r.type == ConnectionType.PLAYER_JOIN)
                .count() / (double) records.size();
            
            // User agent variety (simplified)
            userAgentVariety = 0.3; // default value
            
            // Update avgInterval with the calculated value
            avgInterval = calculatedAvgInterval;
        }
        
        return new MLEngine.ConnectionData(
            connectionCount, avgInterval, stdDev, maxRate,
            burstCount, synRatio, completionRatio, userAgentVariety
        );
    }
    
    /**
     * Hitung rate packet per detik
     */
    private double calculatePacketRate(List<ConnectionData> connections, long now) {
        // Hitung total packets dalam interval tertentu
        long packetCount = connections.size();
        long intervalSeconds = analysisInterval / 1000;
        return (double) packetCount / intervalSeconds;
    }
    
    /**
     * Deteksi pola koneksi mencurigakan
     */
    private int detectSuspiciousPatterns(List<ConnectionData> connections) {
        int score = 0;
        
        // Analisis interval antar koneksi
        if (connections.size() < 3) return 0;
        
        List<Long> intervals = new ArrayList<>();
        for (int i = 1; i < connections.size(); i++) {
            intervals.add(connections.get(i).timestamp - connections.get(i-1).timestamp);
        }
        
        // Deteksi pola intervals yang sama (bot)
        Map<Long, Integer> intervalCounts = new HashMap<>();
        for (Long interval : intervals) {
            intervalCounts.put(interval, intervalCounts.getOrDefault(interval, 0) + 1);
        }
        
        // Cek jika ada interval yang terlalu konsisten (tanda bot)
        for (Map.Entry<Long, Integer> entry : intervalCounts.entrySet()) {
            if (entry.getValue() >= connectionPatternThreshold) {
                score += 30; // Pola terdeteksi
                break;
            }
        }
        
        return score;
    }
    
    /**
     * Analisa tipe koneksi (ping vs join)
     */
    private int analyzeConnectionTypes(List<ConnectionData> connections) {
        long pingCount = connections.stream()
            .filter(c -> c.type == ConnectionType.SERVER_PING)
            .count();
            
        long joinCount = connections.stream()
            .filter(c -> c.type == ConnectionType.PLAYER_LOGIN)
            .count();
            
        // Skor tinggi jika banyak ping tapi sedikit join (scanning)
        if (joinCount == 0 && pingCount > 5) {
            return 25;
        } else if (joinCount > 0) {
            double ratio = (double) pingCount / joinCount;
            if (ratio > 10) { // 10x lebih banyak ping daripada join
                return 20;
            }
        }
        
        return 0;
    }
    
    /**
     * Laporkan aktivitas mencurigakan
     */
    private void reportSuspiciousActivity(String ip, String reason, int score) {
        AttackReport report = attackReports.computeIfAbsent(ip, k -> new AttackReport());
        report.addDetection(reason, score);
        logger.warning("Aktivitas mencurigakan dari " + ip + ": " + reason + " (skor: " + score + ")");
    }
    
    /**
     * Tangani deteksi serangan
     */
    private void handleAttackDetection(String ip, int totalScore) {
        detectedAttacks++;
        logger.severe("SERANGAN TERDETEKSI dari IP " + ip + " dengan skor " + totalScore);
        
        // Tambahkan ke blocklist
        if (!blockedIps.contains(ip)) {
            blockedIps.add(ip);
            
            // Beri tahu ConnectionMonitor untuk memblokir
            reportAttackToFirewall(ip);
            
            // Rekam serangan untuk analisis
            AnalyticsSystem analyticsSystem = plugin.getAnalyticsSystem();
            if (analyticsSystem != null) {
                AttackReport report = attackReports.get(ip);
                String attackType = "Unknown";
                
                if (report != null) {
                    int maxScore = 0;
                    for (Map.Entry<String, Integer> entry : report.detections.entrySet()) {
                        if (entry.getValue() > maxScore) {
                            maxScore = entry.getValue();
                            attackType = entry.getKey();
                        }
                    }
                }
                
                try {
                    analyticsSystem.recordAttack(
                        java.net.InetAddress.getByName(ip), 
                        attackType, 
                        totalScore
                    );
                    analyticsSystem.recordBlockedIp(ip);
                } catch (java.net.UnknownHostException e) {
                    logger.warning("Tidak dapat mengubah string IP ke InetAddress: " + ip + " - " + e.getMessage());
                    // Masih catat IP yang diblokir meskipun gagal mengubah ke InetAddress
                    analyticsSystem.recordBlockedIp(ip);
                }
            }
        }
    }
    
    /**
     * Laporkan serangan ke firewall/connection monitor
     */
    private void reportAttackToFirewall(String ip) {
        // Implementasi blokir IP dengan sistem firewall
        try {
            // Blokir di firewall sistem jika tersedia
            FirewallManager firewallManager = plugin.getFirewallManager();
            if (firewallManager != null && firewallManager.isFirewallAccessible()) {
                firewallManager.blockIpInFirewall(ip);
            }
            
            // Kirim notifikasi melalui NotificationSystem
            NotificationSystem notificationSystem = plugin.getNotificationSystem();
            if (notificationSystem != null) {
                AttackReport report = attackReports.get(ip);
                int score = report != null ? report.getTotalScore() : 100;
                
                // Cari alasan serangan utama
                String attackType = "Unknown";
                if (report != null) {
                    int maxScore = 0;
                    for (Map.Entry<String, Integer> entry : report.detections.entrySet()) {
                        if (entry.getValue() > maxScore) {
                            maxScore = entry.getValue();
                            attackType = entry.getKey();
                        }
                    }
                }
                
                notificationSystem.sendAttackNotification(ip, score, attackType);
            }
            
            logger.info("IP " + ip + " telah ditambahkan ke blocklist");
        } catch (Exception e) {
            logger.severe("Gagal memblokir IP: " + e.getMessage());
        }
    }
    
    /**
     * Bersihkan laporan serangan lama
     */
    private void cleanupAttackReports(long now) {
        // Hapus report yang lebih tua dari 1 jam
        attackReports.entrySet().removeIf(entry -> 
            (now - entry.getValue().lastDetectionTime) > 3600000);
    }
    
    /**
     * Trim data koneksi yang terlalu lama
     */
    private void trimConnectionData() {
        long now = System.currentTimeMillis();
        long cutoffTime = now - (analysisInterval * 2);  // Keep data for 2x analysis interval
        
        connectionData.entrySet().removeIf(entry -> {
            List<ConnectionData> connections = entry.getValue();
            connections.removeIf(c -> c.timestamp < cutoffTime);
            return connections.isEmpty();
        });
    }
    
    /**
     * Kelas untuk menyimpan data koneksi
     */
    private static class ConnectionData {
        final long timestamp;
        final int packetSize;
        final ConnectionType type;
        
        ConnectionData(long timestamp, int packetSize, ConnectionType type) {
            this.timestamp = timestamp;
            this.packetSize = packetSize;
            this.type = type;
        }
    }
    
    /**
     * Enum tipe koneksi
     */
    public enum ConnectionType {
        SERVER_PING,
        PLAYER_LOGIN,
        PLAYER_JOIN
    }
    
    /**
     * Kelas untuk laporan serangan
     */
    private static class AttackReport {
        final Map<String, Integer> detections = new HashMap<>();
        long lastDetectionTime;
        
        void addDetection(String reason, int score) {
            detections.put(reason, detections.getOrDefault(reason, 0) + score);
            lastDetectionTime = System.currentTimeMillis();
        }
        
        int getTotalScore() {
            return detections.values().stream().mapToInt(Integer::intValue).sum();
        }
    }
    
    /**
     * Mendapatkan statistik serangan
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("detectedAttacks", detectedAttacks);
        stats.put("blockedIps", blockedIps.size());
        stats.put("activeMonitoring", !connectionData.isEmpty());
        stats.put("blockedIpList", new ArrayList<>(blockedIps));
        
        return stats;
    }
}