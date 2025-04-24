package id.neonddos;

import org.bukkit.Bukkit;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.scheduler.BukkitRunnable;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Sistem analitik canggih untuk menganalisis pola serangan
 * dan memberikan laporan mendalam tentang aktivitas serangan DDoS
 */
public class AnalyticsSystem {
    
    private final neonddos plugin;
    private final Logger logger;
    
    // Data untuk analisis
    private final Map<String, List<AttackEvent>> attackHistory;
    private final Map<String, TrafficPattern> trafficPatterns;
    private final Map<String, IpReputation> ipReputations;
    
    // Untuk menyimpan data statistik
    private final List<DailyStatistic> dailyStatistics;
    private LocalDateTime lastStatisticReset;
    
    // File database
    private File databaseFile;
    private FileConfiguration database;
    
    // Konfigurasi
    private boolean enableMachineLearning;
    private boolean saveAnalyticsData;
    private int anomalyThreshold;
    private int minDataPointsForAnalysis;
    private int patternMatchThreshold;

    // Batch processing for attack records
    private final List<AttackRecord> pendingAttackRecords = new ArrayList<>();
    private static final int BATCH_SIZE = 50;
    
    public AnalyticsSystem(neonddos plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.attackHistory = new ConcurrentHashMap<>();
        this.trafficPatterns = new ConcurrentHashMap<>();
        this.ipReputations = new ConcurrentHashMap<>();
        this.dailyStatistics = new ArrayList<>();
        this.lastStatisticReset = LocalDateTime.now();
        
        // Muat konfigurasi
        loadConfiguration();
        
        // Inisialisasi database
        loadDatabase();
        
        // Mulai task untuk analisis berkala
        startAnalysisTasks();
        
        logger.info("Sistem analitik canggih diinisialisasi");
    }
    
    /**
     * Muat konfigurasi dari config.yml
     */
    private void loadConfiguration() {
        FileConfiguration config = plugin.getConfig();
        
        enableMachineLearning = config.getBoolean("analytics.enableMachineLearning", true);
        saveAnalyticsData = config.getBoolean("analytics.saveAnalyticsData", true);
        anomalyThreshold = config.getInt("analytics.anomalyThreshold", 3);
        minDataPointsForAnalysis = config.getInt("analytics.minDataPointsForAnalysis", 10);
        patternMatchThreshold = config.getInt("analytics.patternMatchThreshold", 80);
        
        logger.info("Konfigurasi analitik dimuat: " +
                    "ML=" + enableMachineLearning + ", " +
                    "saveData=" + saveAnalyticsData + ", " +
                    "anomalyThreshold=" + anomalyThreshold);
    }
    
    /**
     * Muat database dari file
     */
    private void loadDatabase() {
        try {
            databaseFile = new File(plugin.getDataFolder(), "analytics.yml");
            
            if (!databaseFile.exists()) {
                databaseFile.createNewFile();
            }
            
            database = YamlConfiguration.loadConfiguration(databaseFile);
            
            // Muat data reputasi IP dari database
            if (database.contains("ip-reputation")) {
                for (String ip : database.getConfigurationSection("ip-reputation").getKeys(false)) {
                    int reputation = database.getInt("ip-reputation." + ip + ".score", 0);
                    String category = database.getString("ip-reputation." + ip + ".category", "unknown");
                    int attackCount = database.getInt("ip-reputation." + ip + ".attacks", 0);
                    
                    ipReputations.put(ip, new IpReputation(ip, reputation, category, attackCount));
                }
            }
            
            // Muat statistik harian
            if (database.contains("daily-stats")) {
                for (String dateStr : database.getConfigurationSection("daily-stats").getKeys(false)) {
                    String date = dateStr;
                    int attackCount = database.getInt("daily-stats." + date + ".attacks", 0);
                    int blockedIps = database.getInt("daily-stats." + date + ".blocked-ips", 0);
                    int falsePositives = database.getInt("daily-stats." + date + ".false-positives", 0);
                    
                    dailyStatistics.add(new DailyStatistic(date, attackCount, blockedIps, falsePositives));
                }
            }
            
            logger.info("Database analitik dimuat: " + 
                       ipReputations.size() + " reputasi IP, " +
                       dailyStatistics.size() + " statistik harian");
        } catch (IOException e) {
            logger.log(Level.WARNING, "Gagal memuat database analitik", e);
        }
    }
    
    /**
     * Simpan database ke file
     */
    private void saveDatabase() {
        if (!saveAnalyticsData) {
            return;
        }
        
        try {
            // Simpan data reputasi IP
            for (Map.Entry<String, IpReputation> entry : ipReputations.entrySet()) {
                String ip = entry.getKey();
                IpReputation rep = entry.getValue();
                
                database.set("ip-reputation." + ip + ".score", rep.getReputationScore());
                database.set("ip-reputation." + ip + ".category", rep.getCategory());
                database.set("ip-reputation." + ip + ".attacks", rep.getAttackCount());
                database.set("ip-reputation." + ip + ".last-seen", rep.getLastSeen().toString());
            }
            
            // Simpan statistik harian (batasi maks 90 hari)
            database.set("daily-stats", null); // Clear existing
            int max = Math.min(dailyStatistics.size(), 90);
            for (int i = dailyStatistics.size() - max; i < dailyStatistics.size(); i++) {
                DailyStatistic stat = dailyStatistics.get(i);
                String date = stat.getDate();
                database.set("daily-stats." + date + ".attacks", stat.getAttackCount());
                database.set("daily-stats." + date + ".blocked-ips", stat.getBlockedIpsCount());
                database.set("daily-stats." + date + ".false-positives", stat.getFalsePositiveCount());
            }
            
            // Simpan ke file
            database.save(databaseFile);
            logger.info("Database analitik disimpan");
        } catch (IOException e) {
            logger.log(Level.WARNING, "Gagal menyimpan database analitik", e);
        }
    }
    
    /**
     * Mulai task untuk analisis berkala
     */
    private void startAnalysisTasks() {
        // Task untuk analisis harian
        new BukkitRunnable() {
            @Override
            public void run() {
                analyzeDailyStatistics();
            }
        }.runTaskTimerAsynchronously(plugin, 20 * 60 * 10, 20 * 60 * 60); // Run every hour
        
        // Task untuk analisis pola traffic
        new BukkitRunnable() {
            @Override
            public void run() {
                analyzeTrafficPatterns();
            }
        }.runTaskTimerAsynchronously(plugin, 20 * 60 * 15, 20 * 60 * 15); // Run every 15 minutes
        
        // Task untuk update reputasi IP
        new BukkitRunnable() {
            @Override
            public void run() {
                updateIpReputations();
            }
        }.runTaskTimerAsynchronously(plugin, 20 * 60 * 5, 20 * 60 * 30); // Run every 30 minutes
        
        // Task untuk menyimpan database
        if (saveAnalyticsData) {
            new BukkitRunnable() {
                @Override
                public void run() {
                    saveDatabase();
                }
            }.runTaskTimerAsynchronously(plugin, 20 * 60 * 20, 20 * 60 * 20); // Run every 20 minutes
        }
    }
    
    /**
     * Rekam serangan untuk analisis
     */
    public void recordAttack(InetAddress address, String attackType, int severity) {
        String ip = address.getHostAddress();
        AttackEvent event = new AttackEvent(ip, attackType, severity, LocalDateTime.now());
        
        // Tambahkan ke riwayat serangan
        attackHistory.computeIfAbsent(ip, k -> new ArrayList<>()).add(event);
        
        // Update reputasi IP
        updateIpReputation(ip, attackType, severity);
        
        // Update statistik harian
        updateDailyStatistics(1, 0);
    }

    /**
     * Rekam serangan secara batch untuk analisis
     */
    public void recordAttackBatched(InetAddress address, String attackType, int severity) {
        synchronized(pendingAttackRecords) {
            pendingAttackRecords.add(new AttackRecord(address.getHostAddress(), attackType, severity, LocalDateTime.now()));
            if (pendingAttackRecords.size() >= BATCH_SIZE) {
                processPendingAttacks();
            }
        }
    }

    private void processPendingAttacks() {
        if (pendingAttackRecords.isEmpty()) return;
        
        List<AttackRecord> records;
        synchronized(pendingAttackRecords) {
            records = new ArrayList<>(pendingAttackRecords);
            pendingAttackRecords.clear();
        }
        
        // Process records in batch
        Map<String, List<AttackRecord>> ipGroups = records.stream()
            .collect(Collectors.groupingBy(AttackRecord::getIp));
            
        for (Map.Entry<String, List<AttackRecord>> entry : ipGroups.entrySet()) {
            String ip = entry.getKey();
            List<AttackRecord> ipRecords = entry.getValue();
            
            // Update IP reputation once per IP instead of per record
            int totalSeverity = ipRecords.stream().mapToInt(AttackRecord::getSeverity).sum();
            int avgSeverity = totalSeverity / ipRecords.size();
            String dominantAttackType = findDominantAttackType(ipRecords);
            
            updateIpReputation(ip, dominantAttackType, avgSeverity);
        }
    }

    private String findDominantAttackType(List<AttackRecord> records) {
        Map<String, Long> typeCounts = records.stream()
            .collect(Collectors.groupingBy(AttackRecord::getAttackType, Collectors.counting()));
        
        return typeCounts.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse("unknown");
    }
    
    /**
     * Rekam IP yang diblokir
     */
    public void recordBlockedIp(String ip) {
        // Update statistik harian
        updateDailyStatistics(0, 1);
    }
    
    /**
     * Tandai false positive (jika admin menandai serangan sebagai salah)
     */
    public void markFalsePositive(String ip) {
        // Jika IP memiliki reputasi, update
        if (ipReputations.containsKey(ip)) {
            IpReputation rep = ipReputations.get(ip);
            rep.updateReputationScore(20); // Meningkatkan reputasi
            rep.setFalsePositiveCount(rep.getFalsePositiveCount() + 1);
        }
        
        // Update statistik harian
        LocalDateTime now = LocalDateTime.now();
        String today = now.format(DateTimeFormatter.ISO_LOCAL_DATE);
        
        for (DailyStatistic stat : dailyStatistics) {
            if (stat.getDate().equals(today)) {
                stat.setFalsePositiveCount(stat.getFalsePositiveCount() + 1);
                break;
            }
        }
    }
    
    /**
     * Analisis traffic untuk deteksi anomali
     */
    public List<AnomalyDetection> detectTrafficAnomalies(String ip, List<TrafficDataPoint> trafficData) {
        if (trafficData.size() < minDataPointsForAnalysis || !enableMachineLearning) {
            return new ArrayList<>();
        }
        
        List<AnomalyDetection> anomalies = new ArrayList<>();
        
        // Metode sederhana: deteksi outlier menggunakan z-score
        List<Integer> values = trafficData.stream()
                .map(TrafficDataPoint::getValue)
                .collect(Collectors.toList());
        
        // Hitung mean
        double mean = values.stream().mapToInt(Integer::intValue).average().orElse(0);
        
        // Hitung standard deviation
        double sumSquaredDiff = values.stream()
                .mapToDouble(value -> Math.pow(value - mean, 2))
                .sum();
        double stdDev = Math.sqrt(sumSquaredDiff / values.size());
        
        if (stdDev == 0) return anomalies; // Hindari div by zero
        
        // Deteksi outlier (nilai jauh di atas mean)
        for (int i = 0; i < trafficData.size(); i++) {
            TrafficDataPoint point = trafficData.get(i);
            double zScore = (point.getValue() - mean) / stdDev;
            
            if (zScore > anomalyThreshold) {
                anomalies.add(new AnomalyDetection(
                    "High Traffic Volume", 
                    "Traffic " + (zScore * stdDev) + "x lebih tinggi dari normal",
                    point.getTimestamp(),
                    (int)(zScore * 10) // Severity based on z-score
                ));
            }
        }
        
        return anomalies;
    }
    
    /**
     * Analisis serangan untuk deteksi pola
     */
    public List<PatternDetection> detectAttackPatterns(String ip) {
        List<AttackEvent> attacks = attackHistory.get(ip);
        if (attacks == null || attacks.size() < minDataPointsForAnalysis || !enableMachineLearning) {
            return new ArrayList<>();
        }
        
        List<PatternDetection> patterns = new ArrayList<>();
        
        // Cek pola waktu serangan
        checkTimePatterns(ip, attacks).ifPresent(patterns::add);
        
        // Cek pola tipe serangan
        checkAttackTypePatterns(ip, attacks).ifPresent(patterns::add);
        
        return patterns;
    }
    
    /**
     * Cek pola waktu serangan
     */
    private Optional<PatternDetection> checkTimePatterns(String ip, List<AttackEvent> attacks) {
        // Extract hours of attacks
        int[] hourCounts = new int[24];
        
        for (AttackEvent attack : attacks) {
            int hour = attack.getTimestamp().getHour();
            hourCounts[hour]++;
        }
        
        // Find peak hours (hours with most attacks)
        int maxCount = 0;
        List<Integer> peakHours = new ArrayList<>();
        
        for (int hour = 0; hour < 24; hour++) {
            if (hourCounts[hour] > maxCount) {
                maxCount = hourCounts[hour];
                peakHours.clear();
                peakHours.add(hour);
            } else if (hourCounts[hour] == maxCount && maxCount > 0) {
                peakHours.add(hour);
            }
        }
        
        // Check if peak hours contain significant portion of attacks
        double peakHoursAttackRatio = (double) (peakHours.size() * maxCount) / attacks.size();
        
        if (peakHoursAttackRatio >= 0.5 && maxCount >= 3) { // At least 50% of attacks in peak hours
            StringBuilder peakHoursStr = new StringBuilder();
            for (int i = 0; i < peakHours.size(); i++) {
                peakHoursStr.append(String.format("%02d:00", peakHours.get(i)));
                if (i < peakHours.size() - 1) {
                    peakHoursStr.append(", ");
                }
            }
            
            return Optional.of(new PatternDetection(
                "Time Pattern",
                String.format("%.1f%% serangan terjadi pada jam: %s", peakHoursAttackRatio * 100, peakHoursStr),
                (int)(peakHoursAttackRatio * 100)
            ));
        }
        
        return Optional.empty();
    }
    
    /**
     * Cek pola tipe serangan
     */
    private Optional<PatternDetection> checkAttackTypePatterns(String ip, List<AttackEvent> attacks) {
        // Count attack types
        Map<String, Integer> typeCounts = new HashMap<>();
        
        for (AttackEvent attack : attacks) {
            typeCounts.put(attack.getAttackType(), 
                          typeCounts.getOrDefault(attack.getAttackType(), 0) + 1);
        }
        
        // Find most common attack type
        String mostCommonType = "";
        int maxCount = 0;
        
        for (Map.Entry<String, Integer> entry : typeCounts.entrySet()) {
            if (entry.getValue() > maxCount) {
                maxCount = entry.getValue();
                mostCommonType = entry.getKey();
            }
        }
        
        // Check if most common type is significant
        double typeRatio = (double) maxCount / attacks.size();
        
        if (typeRatio >= 0.7 && maxCount >= 3) { // At least 70% of attacks are the same type
            return Optional.of(new PatternDetection(
                "Attack Type Pattern",
                String.format("%.1f%% serangan menggunakan tipe: %s", typeRatio * 100, mostCommonType),
                (int)(typeRatio * 100)
            ));
        }
        
        return Optional.empty();
    }
    
    /**
     * Update reputasi IP berdasarkan serangan
     */
    private void updateIpReputation(String ip, String attackType, int severity) {
        IpReputation reputation = ipReputations.computeIfAbsent(ip, 
            k -> new IpReputation(ip, 0, "unknown", 0));
        
        // Semakin berat serangan, semakin buruk reputasinya
        int reputationDecrease = severity / 10;
        reputation.updateReputationScore(-reputationDecrease);
        reputation.setAttackCount(reputation.getAttackCount() + 1);
        reputation.setLastSeen(LocalDateTime.now());
        
        // Kategorikan IP berdasarkan jumlah serangan dan severity
        if (reputation.getAttackCount() > 10 || reputation.getReputationScore() < -50) {
            reputation.setCategory("high_threat");
        } else if (reputation.getAttackCount() > 5 || reputation.getReputationScore() < -20) {
            reputation.setCategory("medium_threat");
        } else if (reputation.getAttackCount() > 2) {
            reputation.setCategory("low_threat");
        } else {
            reputation.setCategory("suspicious");
        }
    }
    
    /**
     * Update statistik harian
     */
    private void updateDailyStatistics(int attacks, int blockedIps) {
        LocalDateTime now = LocalDateTime.now();
        String today = now.format(DateTimeFormatter.ISO_LOCAL_DATE);
        
        // Cek apakah perlu reset statistik harian
        if (lastStatisticReset.toLocalDate().isBefore(now.toLocalDate())) {
            lastStatisticReset = now;
        }
        
        // Update atau buat statistik hari ini
        boolean found = false;
        for (DailyStatistic stat : dailyStatistics) {
            if (stat.getDate().equals(today)) {
                stat.setAttackCount(stat.getAttackCount() + attacks);
                stat.setBlockedIpsCount(stat.getBlockedIpsCount() + blockedIps);
                found = true;
                break;
            }
        }
        
        if (!found) {
            dailyStatistics.add(new DailyStatistic(today, attacks, blockedIps, 0));
        }
    }
    
    /**
     * Analisis statistik harian untuk trend
     */
    private void analyzeDailyStatistics() {
        if (dailyStatistics.size() < 7) {
            return; // Butuh minimal data 7 hari
        }
        
        // Hitung rata-rata serangan per hari
        double avgAttacks = dailyStatistics.stream()
            .mapToInt(DailyStatistic::getAttackCount)
            .average()
            .orElse(0);
        
        // Hitung rata-rata IP yang diblokir per hari
        double avgBlocked = dailyStatistics.stream()
            .mapToInt(DailyStatistic::getBlockedIpsCount)
            .average()
            .orElse(0);
        
        // Hitung tren (naik/turun)
        // Bandingkan 3 hari terakhir vs 3 hari sebelumnya
        if (dailyStatistics.size() >= 6) {
            double recent3Days = 0;
            double previous3Days = 0;
            
            for (int i = dailyStatistics.size() - 3; i < dailyStatistics.size(); i++) {
                recent3Days += dailyStatistics.get(i).getAttackCount();
            }
            
            for (int i = dailyStatistics.size() - 6; i < dailyStatistics.size() - 3; i++) {
                previous3Days += dailyStatistics.get(i).getAttackCount();
            }
            
            double trendPct = ((recent3Days - previous3Days) / previous3Days) * 100;
            
            if (Math.abs(trendPct) >= 20) {
                String trendDirection = trendPct > 0 ? "naik" : "turun";
                logger.info(String.format(
                    "Tren serangan: %s %.1f%% dalam 3 hari terakhir (%.1f vs %.1f serangan/hari)", 
                    trendDirection, Math.abs(trendPct), recent3Days/3, previous3Days/3));
                
                // Notifikasi jika tren naik signifikan
                if (trendPct > 30) {
                    NotificationSystem notificationSystem = plugin.getNotificationSystem();
                    if (notificationSystem != null) {
                        notificationSystem.sendInfoNotification(String.format(
                            "PERINGATAN: Serangan meningkat %.1f%% dalam 3 hari terakhir!", trendPct));
                    }
                }
            }
        }
    }
    
    /**
     * Analisis pola traffic untuk deteksi serangan terkoordinasi
     */
    private void analyzeTrafficPatterns() {
        // Implementasi analisis pola traffic
        // Ini akan melihat pola koneksi dan mencoba mendeteksi serangan terkoordinasi
    }
    
    /**
     * Update dan bersihkan database reputasi IP
     */
    private void updateIpReputations() {
        // Hapus IP reputation yang sudah lama tidak muncul (> 30 hari)
        LocalDateTime threshold = LocalDateTime.now().minusDays(30);
        
        ipReputations.entrySet().removeIf(entry -> {
            IpReputation rep = entry.getValue();
            return rep.getLastSeen().isBefore(threshold) && rep.getReputationScore() > -20;
        });
        
        // Perbaiki reputasi IP yang sudah lama tidak menyerang (regenerasi reputasi)
        ipReputations.values().forEach(rep -> {
            if (rep.getLastSeen().isBefore(LocalDateTime.now().minusDays(7))) {
                rep.updateReputationScore(1); // Perlahan memperbaiki reputasi
            }
        });
    }
    
    /**
     * Mendapatkan reputasi IP
     */
    public IpReputation getIpReputation(String ip) {
        return ipReputations.getOrDefault(ip, 
            new IpReputation(ip, 0, "unknown", 0));
    }
    
    /**
     * Mendapatkan statistik analytics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        // Basic stats
        stats.put("totalTrackedIps", ipReputations.size());
        stats.put("highThreatIps", ipReputations.values().stream()
            .filter(r -> r.getCategory().equals("high_threat"))
            .count());
        
        // Attack history stats
        int totalAttacks = attackHistory.values().stream()
            .mapToInt(List::size)
            .sum();
        stats.put("totalRecordedAttacks", totalAttacks);
        
        // Recent attacks (last 24 hours)
        LocalDateTime yesterday = LocalDateTime.now().minusDays(1);
        int recentAttacks = (int)attackHistory.values().stream()
            .flatMap(List::stream)
            .filter(a -> a.getTimestamp().isAfter(yesterday))
            .count();
        stats.put("attacksLast24Hours", recentAttacks);
        
        // Daily stats for last 7 days
        List<Map<String, Object>> dailyStats = new ArrayList<>();
        int daysToShow = Math.min(dailyStatistics.size(), 7);
        
        for (int i = dailyStatistics.size() - daysToShow; i < dailyStatistics.size(); i++) {
            DailyStatistic ds = dailyStatistics.get(i);
            Map<String, Object> day = new HashMap<>();
            day.put("date", ds.getDate());
            day.put("attacks", ds.getAttackCount());
            day.put("blockedIps", ds.getBlockedIpsCount());
            day.put("falsePositives", ds.getFalsePositiveCount());
            dailyStats.add(day);
        }
        stats.put("dailyStats", dailyStats);
        
        return stats;
    }
    
    /**
     * Class untuk menyimpan data reputasi IP
     */
    public static class IpReputation {
        private final String ip;
        private int reputationScore;
        private String category;
        private int attackCount;
        private int falsePositiveCount;
        private LocalDateTime lastSeen;
        
        public IpReputation(String ip, int reputationScore, String category, int attackCount) {
            this.ip = ip;
            this.reputationScore = reputationScore;
            this.category = category;
            this.attackCount = attackCount;
            this.falsePositiveCount = 0;
            this.lastSeen = LocalDateTime.now();
        }
        
        public void updateReputationScore(int change) {
            reputationScore += change;
            
            // Batasi range reputasi
            if (reputationScore < -100) reputationScore = -100;
            if (reputationScore > 100) reputationScore = 100;
        }

        public String getIp() { return ip; }
        public int getReputationScore() { return reputationScore; }
        public String getCategory() { return category; }
        public void setCategory(String category) { this.category = category; }
        public int getAttackCount() { return attackCount; }
        public void setAttackCount(int attackCount) { this.attackCount = attackCount; }
        public LocalDateTime getLastSeen() { return lastSeen; }
        public void setLastSeen(LocalDateTime lastSeen) { this.lastSeen = lastSeen; }
        public int getFalsePositiveCount() { return falsePositiveCount; }
        public void setFalsePositiveCount(int falsePositiveCount) { this.falsePositiveCount = falsePositiveCount; }
    }
    
    /**
     * Class untuk menyimpan event serangan
     */
    private static class AttackEvent {
        private final String ip;
        private final String attackType;
        private final int severity;
        private final LocalDateTime timestamp;
        
        public AttackEvent(String ip, String attackType, int severity, LocalDateTime timestamp) {
            this.ip = ip;
            this.attackType = attackType;
            this.severity = severity;
            this.timestamp = timestamp;
        }
        
        public String getIp() { return ip; }
        public String getAttackType() { return attackType; }
        public int getSeverity() { return severity; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    /**
     * Class untuk menyimpan record serangan
     */
    private static class AttackRecord {
        private final String ip;
        private final String attackType;
        private final int severity;
        private final LocalDateTime timestamp;
        
        public AttackRecord(String ip, String attackType, int severity, LocalDateTime timestamp) {
            this.ip = ip;
            this.attackType = attackType;
            this.severity = severity;
            this.timestamp = timestamp;
        }
        
        public String getIp() { return ip; }
        public String getAttackType() { return attackType; }
        public int getSeverity() { return severity; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    /**
     * Class untuk data traffic
     */
    public static class TrafficDataPoint {
        private final int value;
        private final LocalDateTime timestamp;
        
        public TrafficDataPoint(int value, LocalDateTime timestamp) {
            this.value = value;
            this.timestamp = timestamp;
        }
        
        public int getValue() { return value; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    /**
     * Class untuk deteksi anomali
     */
    public static class AnomalyDetection {
        private final String type;
        private final String description;
        private final LocalDateTime timestamp;
        private final int severity;
        
        public AnomalyDetection(String type, String description, LocalDateTime timestamp, int severity) {
            this.type = type;
            this.description = description;
            this.timestamp = timestamp;
            this.severity = severity;
        }
        
        public String getType() { return type; }
        public String getDescription() { return description; }
        public LocalDateTime getTimestamp() { return timestamp; }
        public int getSeverity() { return severity; }
    }
    
    /**
     * Class untuk deteksi pola
     */
    public static class PatternDetection {
        private final String type;
        private final String description;
        private final int confidence;
        
        public PatternDetection(String type, String description, int confidence) {
            this.type = type;
            this.description = description;
            this.confidence = confidence;
        }
        
        public String getType() { return type; }
        public String getDescription() { return description; }
        public int getConfidence() { return confidence; }
    }
    
    /**
     * Class untuk menyimpan pola traffic
     */
    private static class TrafficPattern {
        private final String name;
        private final Map<Integer, Integer> hourlyDistribution;
        
        public TrafficPattern(String name) {
            this.name = name;
            this.hourlyDistribution = new HashMap<>();
            for (int i = 0; i < 24; i++) {
                hourlyDistribution.put(i, 0);
            }
        }
        
        public void addDataPoint(LocalDateTime time, int value) {
            int hour = time.getHour();
            hourlyDistribution.put(hour, hourlyDistribution.get(hour) + value);
        }
        
        public String getName() { return name; }
        public Map<Integer, Integer> getHourlyDistribution() { return hourlyDistribution; }
    }
    
    /**
     * Class untuk statistik harian
     */
    private static class DailyStatistic {
        private final String date;
        private int attackCount;
        private int blockedIpsCount;
        private int falsePositiveCount;
        
        public DailyStatistic(String date, int attackCount, int blockedIpsCount, int falsePositiveCount) {
            this.date = date;
            this.attackCount = attackCount;
            this.blockedIpsCount = blockedIpsCount;
            this.falsePositiveCount = falsePositiveCount;
        }
        
        public String getDate() { return date; }
        public int getAttackCount() { return attackCount; }
        public void setAttackCount(int attackCount) { this.attackCount = attackCount; }
        public int getBlockedIpsCount() { return blockedIpsCount; }
        public void setBlockedIpsCount(int blockedIpsCount) { this.blockedIpsCount = blockedIpsCount; }
        public int getFalsePositiveCount() { return falsePositiveCount; }
        public void setFalsePositiveCount(int falsePositiveCount) { this.falsePositiveCount = falsePositiveCount; }
    }
}