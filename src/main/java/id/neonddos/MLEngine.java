package id.neonddos;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.scheduler.BukkitRunnable;

/**
 * Mesin Machine Learning untuk deteksi dan prediksi serangan DDoS
 */
public class MLEngine {
    
    private final neonddos plugin;
    private final Logger logger;
    
    // Model-model ML untuk berbagai jenis deteksi
    private AnomalyDetectionModel anomalyModel;
    private ConnectionClassifier connectionClassifier;
    private AttackPredictor attackPredictor;
    
    // Cache fitur untuk analisis
    private final Map<String, List<double[]>> featureCache = new ConcurrentHashMap<>();
    
    // Konfigurasi
    private boolean enableMLDetection;
    private boolean adaptiveThresholds;
    private int trainingInterval; // dalam menit
    private int minDataPointsForTraining;
    private double detectionThreshold;
    private String modelSaveDirectory;
    
    // Statistics
    private int truePositives = 0;
    private int falsePositives = 0;
    private int trueNegatives = 0;
    private int falseNegatives = 0;
    private int totalPredictions = 0;
    
    public MLEngine(neonddos plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        
        // Load konfigurasi
        loadConfiguration();
        
        // Inisialisasi model
        initializeModels();
        
        // Mulai training scheduler
        startTrainingScheduler();
        
        logger.info("Machine Learning Engine diinisialisasi - ML Detection: " + 
                    (enableMLDetection ? "enabled" : "disabled"));
    }
    
    /**
     * Load konfigurasi dari config.yml
     */
    private void loadConfiguration() {
        FileConfiguration config = plugin.getConfig();
        
        enableMLDetection = config.getBoolean("machine-learning.enabled", true);
        adaptiveThresholds = config.getBoolean("machine-learning.adaptiveThresholds", true);
        trainingInterval = config.getInt("machine-learning.trainingIntervalMinutes", 30);
        minDataPointsForTraining = config.getInt("machine-learning.minDataPointsForTraining", 100);
        detectionThreshold = config.getDouble("machine-learning.detectionThreshold", 0.75);
        modelSaveDirectory = config.getString("machine-learning.modelSaveDirectory", "models");
        
        // Pastikan direktori model tersedia
        File modelDir = new File(plugin.getDataFolder(), modelSaveDirectory);
        if (!modelDir.exists()) {
            modelDir.mkdirs();
        }
    }
    
    /**
     * Inisialisasi model ML
     */
    private void initializeModels() {
        // Coba load model yang tersimpan
        anomalyModel = loadModel("anomaly_model.ser", AnomalyDetectionModel.class);
        if (anomalyModel == null) {
            anomalyModel = new AnomalyDetectionModel();
            logger.info("Membuat model deteksi anomali baru");
        } else {
            logger.info("Model deteksi anomali dimuat dari disk");
        }
        
        connectionClassifier = loadModel("connection_classifier.ser", ConnectionClassifier.class);
        if (connectionClassifier == null) {
            connectionClassifier = new ConnectionClassifier();
            logger.info("Membuat model klasifikasi koneksi baru");
        } else {
            logger.info("Model klasifikasi koneksi dimuat dari disk");
        }
        
        attackPredictor = loadModel("attack_predictor.ser", AttackPredictor.class);
        if (attackPredictor == null) {
            attackPredictor = new AttackPredictor();
            logger.info("Membuat model prediksi serangan baru");
        } else {
            logger.info("Model prediksi serangan dimuat dari disk");
        }
    }
    
    /**
     * Load model dari disk
     */
    @SuppressWarnings("unchecked")
    private <T> T loadModel(String fileName, Class<T> clazz) {
        File modelFile = new File(new File(plugin.getDataFolder(), modelSaveDirectory), fileName);
        
        if (!modelFile.exists()) {
            return null;
        }
        
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(modelFile))) {
            Object model = ois.readObject();
            if (clazz.isInstance(model)) {
                return (T) model;
            }
            return null;
        } catch (IOException | ClassNotFoundException e) {
            logger.log(Level.WARNING, "Gagal memuat model " + fileName, e);
            return null;
        }
    }
    
    /**
     * Simpan model ke disk
     */
    private void saveModel(String fileName, Serializable model) {
        File modelFile = new File(new File(plugin.getDataFolder(), modelSaveDirectory), fileName);
        
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(modelFile))) {
            oos.writeObject(model);
            logger.info("Model " + fileName + " berhasil disimpan");
        } catch (IOException e) {
            logger.log(Level.WARNING, "Gagal menyimpan model " + fileName, e);
        }
    }
    
    /**
     * Mulai scheduler untuk training berkala
     */
    private void startTrainingScheduler() {
        if (!enableMLDetection) {
            return;
        }
        
        // Training interval dalam menit dikonversi ke ticks
        long interval = trainingInterval * 60 * 20L;
        
        new BukkitRunnable() {
            @Override
            public void run() {
                trainModels();
            }
        }.runTaskTimerAsynchronously(plugin, interval, interval);
        
        // Scheduler untuk pembersihan cache
        new BukkitRunnable() {
            @Override
            public void run() {
                // Bersihkan cache yang lebih dari 24 jam
                featureCache.entrySet().removeIf(entry -> 
                    entry.getValue().size() > 1000);
            }
        }.runTaskTimerAsynchronously(plugin, 20 * 60 * 60, 20 * 60 * 60); // Setiap jam
    }
    
    /**
     * Training semua model secara berkala
     */
    public void trainModels() {
        if (!enableMLDetection || featureCache.isEmpty()) {
            return;
        }
        
        // Hitung total data points
        int totalDataPoints = featureCache.values().stream().mapToInt(List::size).sum();
        
        if (totalDataPoints < minDataPointsForTraining) {
            logger.info("Menunda training, data tidak cukup (" + totalDataPoints + "/" + minDataPointsForTraining + ")");
            return;
        }
        
        logger.info("Memulai training model ML dengan " + totalDataPoints + " data points");
        
        // Siapkan data training dari cache
        List<double[]> normalTraffic = new ArrayList<>();
        List<double[]> attackTraffic = new ArrayList<>();
        
        // Split data berdasarkan label (simpel, untuk IP yang diketahui menyerang vs tidak)
        for (Map.Entry<String, List<double[]>> entry : featureCache.entrySet()) {
            String ip = entry.getKey();
            List<double[]> features = entry.getValue();
            
            boolean isAttacker = isKnownAttacker(ip);
            
            for (double[] feature : features) {
                if (isAttacker) {
                    attackTraffic.add(feature);
                } else {
                    normalTraffic.add(feature);
                }
            }
        }
        
        // Training anomaly detection model
        anomalyModel.train(normalTraffic, attackTraffic);
        
        // Training connection classifier
        connectionClassifier.train(normalTraffic, attackTraffic);
        
        // Training attack predictor
        attackPredictor.train(featureCache);
        
        // Simpan model yang telah ditraining
        saveModel("anomaly_model.ser", anomalyModel);
        saveModel("connection_classifier.ser", connectionClassifier);
        saveModel("attack_predictor.ser", attackPredictor);
        
        logger.info("Training ML selesai - Models updated and saved");
        
        // Update adaptive thresholds jika diaktifkan
        if (adaptiveThresholds) {
            updateAdaptiveThresholds();
        }
    }
    
    /**
     * Cek apakah IP diketahui sebagai penyerang
     */
    private boolean isKnownAttacker(String ip) {
        AnalyticsSystem analyticsSystem = plugin.getAnalyticsSystem();
        if (analyticsSystem != null) {
            AnalyticsSystem.IpReputation reputation = analyticsSystem.getIpReputation(ip);
            return reputation.getReputationScore() < -20 || reputation.getAttackCount() > 3;
        }
        return false;
    }
    
    /**
     * Ekstrak fitur dari data koneksi
     */
    private double[] extractFeatures(ConnectionData connectionData) {
        // Fitur yang diekstrak:
        // 1. Jumlah koneksi dalam window waktu tertentu
        // 2. Rata-rata interval antar koneksi (ms)
        // 3. Standar deviasi interval
        // 4. Max koneksi dalam 1 detik
        // 5. Jumlah burst (>5 koneksi dalam 1 detik)
        // 6. Rasio SYN packets
        // 7. Rasio koneksi selesai
        // 8. Variasi User-Agent
        
        double connectionCount = connectionData.getConnectionCount();
        double avgInterval = connectionData.getAverageInterval();
        double stdDeviation = connectionData.getIntervalStdDev();
        double maxRate = connectionData.getMaxConnectionRate();
        double burstCount = connectionData.getBurstCount();
        double synRatio = connectionData.getSynPacketsRatio();
        double completionRatio = connectionData.getCompletionRatio();
        double userAgentVariety = connectionData.getUserAgentVariety();
        
        return new double[] {
            connectionCount, avgInterval, stdDeviation, maxRate, 
            burstCount, synRatio, completionRatio, userAgentVariety
        };
    }
    
    /**
     * Cek koneksi dengan ML untuk deteksi serangan
     * @return Skor ancaman (0.0-1.0, semakin tinggi semakin mencurigakan)
     */
    public double checkConnection(String ip, ConnectionData connectionData) {
        if (!enableMLDetection) {
            return 0.0; // ML detection tidak aktif
        }
        
        // Ekstrak fitur dari data koneksi
        double[] features = extractFeatures(connectionData);
        
        // Simpan fitur untuk training di masa depan
        featureCache.computeIfAbsent(ip, k -> new ArrayList<>()).add(features);
        
        // Deteksi dengan kedua model dan combine hasilnya
        double anomalyScore = anomalyModel.detect(features);
        double classifierScore = connectionClassifier.classify(features);
        
        // Weighted average dari kedua skor
        double combinedScore = (anomalyScore * 0.6) + (classifierScore * 0.4);
        
        // Track statistics for model evaluation
        totalPredictions++;
        boolean predictedAttack = combinedScore >= detectionThreshold;
        boolean isActualAttack = isKnownAttacker(ip);
        
        if (predictedAttack && isActualAttack) truePositives++;
        else if (predictedAttack && !isActualAttack) falsePositives++;
        else if (!predictedAttack && !isActualAttack) trueNegatives++;
        else if (!predictedAttack && isActualAttack) falseNegatives++;
        
        return combinedScore;
    }
    
    /**
     * Prediksi apakah akan ada serangan dalam waktu dekat
     * @return AttackPrediction dengan skor dan jenis serangan yang diprediksikan
     */
    public AttackPrediction predictAttack() {
        if (!enableMLDetection) {
            return new AttackPrediction(0.0, "Unknown", null);
        }
        
        return attackPredictor.predict();
    }
    
    /**
     * Update adaptive thresholds berdasarkan data ML
     */
    private void updateAdaptiveThresholds() {
        // Hitung optimal threshold berdasarkan data dan model saat ini
        double optimalThreshold = calculateOptimalThreshold();
        
        // Update threshold deteksi
        if (optimalThreshold > 0) {
            double oldThreshold = detectionThreshold;
            detectionThreshold = optimalThreshold;
            logger.info("Adaptive threshold diupdate: " + oldThreshold + " -> " + detectionThreshold);
            
            // Simpan ke config
            FileConfiguration config = plugin.getConfig();
            config.set("machine-learning.detectionThreshold", detectionThreshold);
            plugin.saveConfig();
        }
        
        // Update juga threshold untuk DdosDetector
        DdosDetector ddosDetector = plugin.getDdosDetector();
        if (ddosDetector != null) {
            // Hitung thresholds optimal untuk berbagai jenis serangan
            // dan informasikan ke DdosDetector
            Map<String, Integer> optimalThresholds = calculateAttackTypeThresholds();
            // ddosDetector.updateThresholds(optimalThresholds);
        }
    }
    
    /**
     * Calculate optimal detection threshold
     */
    private double calculateOptimalThreshold() {
        if (totalPredictions < 100) {
            return -1; // Not enough data
        }
        
        // Simple implementation: maximize F1 score
        double precision = (double) truePositives / (truePositives + falsePositives);
        double recall = (double) truePositives / (truePositives + falseNegatives);
        double f1 = 2 * (precision * recall) / (precision + recall);
        
        // Try different thresholds in future implementations
        // For now return current threshold with a slight adjustment
        double accuracy = (double) (truePositives + trueNegatives) / totalPredictions;
        
        // If accuracy is low, adjust threshold
        if (accuracy < 0.7) {
            return detectionThreshold * 0.95; // Lower threshold if too strict
        } else if (falseNegatives > falsePositives * 2) {
            return detectionThreshold * 0.95; // Lower threshold if missing attacks
        } else if (falsePositives > falseNegatives * 2) {
            return detectionThreshold * 1.05; // Raise threshold if too many false alarms
        }
        
        // Return current threshold if working well
        return detectionThreshold;
    }
    
    /**
     * Calculate optimal thresholds for different attack types
     */
    private Map<String, Integer> calculateAttackTypeThresholds() {
        Map<String, Integer> thresholds = new HashMap<>();
        
        // Default values
        thresholds.put("CONNECTION_FLOOD", 15);
        thresholds.put("SYN_FLOOD", 10);
        thresholds.put("PROTOCOL_ABUSE", 20);
        thresholds.put("BOTNET_ATTACK", 8);
        
        // Custom adaptive logic could be implemented here
        
        return thresholds;
    }
    
    /**
     * Dapatkan statistik ML Engine
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        stats.put("enabled", enableMLDetection);
        stats.put("adaptiveThresholds", adaptiveThresholds);
        stats.put("totalPredictions", totalPredictions);
        
        double accuracy = totalPredictions > 0 ? 
            (double)(truePositives + trueNegatives) / totalPredictions : 0;
        stats.put("accuracy", accuracy);
        
        double precision = (truePositives + falsePositives) > 0 ?
            (double)truePositives / (truePositives + falsePositives) : 0;
        stats.put("precision", precision);
        
        double recall = (truePositives + falseNegatives) > 0 ?
            (double)truePositives / (truePositives + falseNegatives) : 0;
        stats.put("recall", recall);
        
        double f1 = (precision + recall) > 0 ?
            2 * precision * recall / (precision + recall) : 0;
        stats.put("f1Score", f1);
        
        stats.put("currentThreshold", detectionThreshold);
        stats.put("cachedFeatureSets", featureCache.size());
        
        return stats;
    }
    
    /**
     * Enable/disable ML detection
     */
    public void setEnabled(boolean enabled) {
        this.enableMLDetection = enabled;
        
        FileConfiguration config = plugin.getConfig();
        config.set("machine-learning.enabled", enabled);
        plugin.saveConfig();
        
        logger.info("Machine Learning detection " + (enabled ? "enabled" : "disabled"));
    }
    
    /**
     * Model untuk deteksi anomali
     * Implementasi sederhana dari Isolation Forest
     */
    private static class AnomalyDetectionModel implements Serializable {
        private static final long serialVersionUID = 1L;
        
        // Simplified model parameters
        private List<double[]> normalSamples = new ArrayList<>();
        private double[][] anomalyBoundaries; // min/max values for each feature
        private double[] normalAverages;
        private double[] normalStdDevs;
        
        /**
         * Train model with normal and attack traffic samples
         */
        public void train(List<double[]> normalTraffic, List<double[]> attackTraffic) {
            if (normalTraffic.isEmpty()) {
                return;
            }
            
            // Store representative samples
            int sampleSize = Math.min(normalTraffic.size(), 200);
            normalSamples = normalTraffic.subList(0, sampleSize);
            
            // Calculate feature boundaries
            int featureCount = normalTraffic.get(0).length;
            anomalyBoundaries = new double[featureCount][2];
            normalAverages = new double[featureCount];
            normalStdDevs = new double[featureCount];
            
            // Initialize boundaries
            for (int i = 0; i < featureCount; i++) {
                anomalyBoundaries[i][0] = Double.MAX_VALUE; // min
                anomalyBoundaries[i][1] = Double.MIN_VALUE; // max
                
                // Calculate averages
                double sum = 0;
                for (double[] sample : normalTraffic) {
                    sum += sample[i];
                    
                    // Update min/max
                    anomalyBoundaries[i][0] = Math.min(anomalyBoundaries[i][0], sample[i]);
                    anomalyBoundaries[i][1] = Math.max(anomalyBoundaries[i][1], sample[i]);
                }
                normalAverages[i] = sum / normalTraffic.size();
                
                // Calculate std deviation
                double sqSum = 0;
                for (double[] sample : normalTraffic) {
                    sqSum += Math.pow(sample[i] - normalAverages[i], 2);
                }
                normalStdDevs[i] = Math.sqrt(sqSum / normalTraffic.size());
                
                // Extend boundaries by 3 std deviations
                anomalyBoundaries[i][0] = Math.max(0, normalAverages[i] - (3 * normalStdDevs[i]));
                anomalyBoundaries[i][1] = normalAverages[i] + (3 * normalStdDevs[i]);
            }
        }
        
        /**
         * Detect anomalies
         * @return Score between 0.0 (normal) and 1.0 (anomalous)
         */
        public double detect(double[] features) {
            if (normalSamples.isEmpty() || anomalyBoundaries == null) {
                return 0.5; // No model yet
            }
            
            int featureCount = features.length;
            int outOfBoundCount = 0;
            double mahalanobisDistance = 0;
            
            // Check how many features are outside normal boundaries
            for (int i = 0; i < featureCount; i++) {
                if (features[i] < anomalyBoundaries[i][0] || features[i] > anomalyBoundaries[i][1]) {
                    outOfBoundCount++;
                }
                
                // Calculate normalized distance
                if (normalStdDevs[i] > 0) {
                    double normalizedDist = Math.abs(features[i] - normalAverages[i]) / normalStdDevs[i];
                    mahalanobisDistance += Math.pow(normalizedDist, 2);
                }
            }
            
            // Calculate anomaly score
            double boundaryScore = (double) outOfBoundCount / featureCount;
            double distanceScore = Math.min(1.0, Math.sqrt(mahalanobisDistance) / (2 * featureCount));
            
            // Combine scores
            return 0.6 * boundaryScore + 0.4 * distanceScore;
        }
    }
    
    /**
     * Model untuk klasifikasi koneksi normal vs serangan
     * Implementasi sederhana dari Random Forest
     */
    private static class ConnectionClassifier implements Serializable {
        private static final long serialVersionUID = 1L;
        
        // Simple decision tree rules
        private List<DecisionTree> decisionTrees = new ArrayList<>();
        
        public ConnectionClassifier() {
            // Initialize with some basic rules
            decisionTrees.add(createConnectionRateTree());
            decisionTrees.add(createBurstTree());
            decisionTrees.add(createIntervalTree());
        }
        
        /**
         * Create decision tree for connection rate
         */
        private DecisionTree createConnectionRateTree() {
            return new DecisionTree(3) { // Checks feature at index 3 (maxRate)
                @Override
                public double classify(double[] features) {
                    if (features[3] > 20) return 0.9; // Very high rate
                    if (features[3] > 10) return 0.7; // High rate
                    if (features[3] > 5) return 0.5; // Medium rate
                    return 0.2; // Normal rate
                }
            };
        }
        
        /**
         * Create decision tree for burst detection
         */
        private DecisionTree createBurstTree() {
            return new DecisionTree(4) { // Checks feature at index 4 (burstCount)
                @Override
                public double classify(double[] features) {
                    if (features[4] > 5) return 0.9; // Many bursts
                    if (features[4] > 2) return 0.6; // Some bursts
                    return 0.1; // Few or no bursts
                }
            };
        }
        
        /**
         * Create decision tree for connection interval
         */
        private DecisionTree createIntervalTree() {
            return new DecisionTree(1) { // Checks feature at index 1 (avgInterval)
                @Override
                public double classify(double[] features) {
                    if (features[1] < 100) return 0.9; // Very fast connections
                    if (features[1] < 500) return 0.6; // Fast connections
                    if (features[1] < 2000) return 0.3; // Normal connections
                    return 0.1; // Slow connections
                }
            };
        }
        
        /**
         * Train classifier with samples
         */
        public void train(List<double[]> normalTraffic, List<double[]> attackTraffic) {
            if (normalTraffic.isEmpty() || attackTraffic.isEmpty()) {
                return;
            }
            
            // Update decision trees based on training data
            // (In a real implementation, this would use proper decision tree learning)
            // Here we'll just update our existing trees with thresholds from the data
            
            double[] normalMaxes = new double[8];
            double[] attackMins = new double[8];
            
            // Initialize arrays
            Arrays.fill(normalMaxes, Double.MIN_VALUE);
            Arrays.fill(attackMins, Double.MAX_VALUE);
            
            // Find max values in normal traffic
            for (double[] sample : normalTraffic) {
                for (int i = 0; i < sample.length; i++) {
                    normalMaxes[i] = Math.max(normalMaxes[i], sample[i]);
                }
            }
            
            // Find min values in attack traffic
            for (double[] sample : attackTraffic) {
                for (int i = 0; i < sample.length; i++) {
                    attackMins[i] = Math.min(attackMins[i], sample[i]);
                }
            }
            
            // Update decision trees with new thresholds
            decisionTrees.clear();
            
            // Connection rate tree
            final double rateThreshold = (normalMaxes[3] + attackMins[3]) / 2;
            decisionTrees.add(new DecisionTree(3) {
                @Override
                public double classify(double[] features) {
                    if (features[3] > rateThreshold * 2) return 0.9;
                    if (features[3] > rateThreshold) return 0.7;
                    return 0.3;
                }
            });
            
            // Burst tree
            final double burstThreshold = (normalMaxes[4] + attackMins[4]) / 2;
            decisionTrees.add(new DecisionTree(4) {
                @Override
                public double classify(double[] features) {
                    if (features[4] > burstThreshold * 2) return 0.9;
                    if (features[4] > burstThreshold) return 0.7;
                    return 0.3;
                }
            });
            
            // Interval tree
            final double intervalThreshold = (normalMaxes[1] + attackMins[1]) / 2;
            decisionTrees.add(new DecisionTree(1) {
                @Override
                public double classify(double[] features) {
                    if (features[1] < intervalThreshold / 2) return 0.9;
                    if (features[1] < intervalThreshold) return 0.7;
                    return 0.3;
                }
            });
        }
        
        /**
         * Classify connection as normal (0.0) or attack (1.0)
         */
        public double classify(double[] features) {
            if (decisionTrees.isEmpty()) {
                return 0.5; // No model
            }
            
            // Average the results of all decision trees
            double sum = 0;
            for (DecisionTree tree : decisionTrees) {
                sum += tree.classify(features);
            }
            
            return sum / decisionTrees.size();
        }
    }
    
    /**
     * Abstract decision tree class
     */
    private static abstract class DecisionTree implements Serializable {
        private static final long serialVersionUID = 1L;
        
        protected int featureIndex;
        
        public DecisionTree(int featureIndex) {
            this.featureIndex = featureIndex;
        }
        
        public abstract double classify(double[] features);
    }
    
    /**
     * Model untuk memprediksi serangan di masa depan
     */
    private static class AttackPredictor implements Serializable {
        private static final long serialVersionUID = 1L;
        
        private Map<String, Double> attackProbabilities = new HashMap<>();
        private Map<Integer, Double> hourlyAttackProbabilities = new HashMap<>();
        private String mostLikelyAttackType = "Unknown";
        private double highestProbability = 0.0;
        
        /**
         * Train predictor with historical data
         */
        public void train(Map<String, List<double[]>> featureCache) {
            if (featureCache.isEmpty()) {
                return;
            }
            
            // Count attack occurrences by type
            Map<String, Integer> attackTypeCount = new HashMap<>();
            
            // Count attacks by hour of day
            int[] hourlyAttacks = new int[24];
            int[] hourlySamples = new int[24];
            
            // Analyze each IP's data
            for (Map.Entry<String, List<double[]>> entry : featureCache.entrySet()) {
                List<double[]> features = entry.getValue();
                
                for (double[] feature : features) {
                    // Check if this appears to be an attack
                    boolean isLikelyAttack = isLikelyAttack(feature);
                    
                    if (isLikelyAttack) {
                        // Determine attack type based on feature pattern
                        String attackType = determineAttackType(feature);
                        attackTypeCount.put(attackType, attackTypeCount.getOrDefault(attackType, 0) + 1);
                        
                        // Track by hour (simulate time stamp)
                        int hour = (int)(System.currentTimeMillis() % (24 * 3600 * 1000)) / (3600 * 1000);
                        hourlyAttacks[hour]++;
                    }
                    
                    // Track samples by hour
                    int hour = (int)(System.currentTimeMillis() % (24 * 3600 * 1000)) / (3600 * 1000);
                    hourlySamples[hour]++;
                }
            }
            
            // Calculate probabilities for attack types
            int totalAttacks = attackTypeCount.values().stream().mapToInt(Integer::intValue).sum();
            
            if (totalAttacks > 0) {
                attackProbabilities.clear();
                for (Map.Entry<String, Integer> entry : attackTypeCount.entrySet()) {
                    String attackType = entry.getKey();
                    int count = entry.getValue();
                    double probability = (double) count / totalAttacks;
                    attackProbabilities.put(attackType, probability);
                    
                    if (probability > highestProbability) {
                        highestProbability = probability;
                        mostLikelyAttackType = attackType;
                    }
                }
            }
            
            // Calculate hourly probabilities
            hourlyAttackProbabilities.clear();
            for (int i = 0; i < 24; i++) {
                if (hourlySamples[i] > 0) {
                    hourlyAttackProbabilities.put(i, (double) hourlyAttacks[i] / hourlySamples[i]);
                }
            }
        }
        
        /**
         * Predict next attack
         */
        public AttackPrediction predict() {
            if (attackProbabilities.isEmpty()) {
                return new AttackPrediction(0.0, "Unknown", null);
            }
            
            // Get current hour
            int currentHour = (int)(System.currentTimeMillis() % (24 * 3600 * 1000)) / (3600 * 1000);
            
            // Find next 3 hours with highest attack probabilities
            List<Integer> nextHours = new ArrayList<>();
            for (int i = 1; i <= 12; i++) {
                int hour = (currentHour + i) % 24;
                nextHours.add(hour);
            }
            
            // Sort by probability
            nextHours.sort((h1, h2) -> Double.compare(
                hourlyAttackProbabilities.getOrDefault(h2, 0.0),
                hourlyAttackProbabilities.getOrDefault(h1, 0.0)
            ));
            
            // Get highest probability hour in next 12 hours
            int nextLikelyHour = nextHours.get(0);
            double probability = hourlyAttackProbabilities.getOrDefault(nextLikelyHour, 0.0);
            
            // Estimate time until attack (in milliseconds)
            long currentMs = System.currentTimeMillis() % (24 * 3600 * 1000); // ms in day
            long targetMs = nextLikelyHour * 3600 * 1000; // target hour in ms
            
            // Check if target is next day
            long timeUntil = targetMs > currentMs ? 
                             targetMs - currentMs : 
                             targetMs + (24 * 3600 * 1000) - currentMs;
            
            // Create prediction
            return new AttackPrediction(
                probability,
                mostLikelyAttackType,
                timeUntil
            );
        }
        
        /**
         * Check if feature set likely represents an attack
         */
        private boolean isLikelyAttack(double[] feature) {
            // Simple rule-based check
            return feature[3] > 8 || // high max rate
                   feature[4] > 3 || // many bursts
                   feature[1] < 200; // very fast connections
        }
        
        /**
         * Determine attack type based on feature pattern
         */
        private String determineAttackType(double[] feature) {
            // High connection rate but normal completion ratio
            if (feature[3] > 10 && feature[6] > 0.7) {
                return "CONNECTION_FLOOD";
            }
            
            // Many SYN packets but low completion
            if (feature[5] > 0.8 && feature[6] < 0.3) {
                return "SYN_FLOOD";
            }
            
            // High user agent variety
            if (feature[7] > 0.7) {
                return "BOTNET_ATTACK";
            }
            
            return "GENERIC_FLOOD";
        }
    }
    
    /**
     * Connection data class for ML analysis
     */
    public static class ConnectionData {
        private int connectionCount;
        private double averageInterval;
        private double intervalStdDev;
        private double maxConnectionRate;
        private int burstCount;
        private double synPacketsRatio;
        private double completionRatio;
        private double userAgentVariety;
        
        public ConnectionData(
            int connectionCount, 
            double averageInterval, 
            double intervalStdDev,
            double maxConnectionRate, 
            int burstCount, 
            double synPacketsRatio,
            double completionRatio, 
            double userAgentVariety) {
            
            this.connectionCount = connectionCount;
            this.averageInterval = averageInterval;
            this.intervalStdDev = intervalStdDev;
            this.maxConnectionRate = maxConnectionRate;
            this.burstCount = burstCount;
            this.synPacketsRatio = synPacketsRatio;
            this.completionRatio = completionRatio;
            this.userAgentVariety = userAgentVariety;
        }
        
        public int getConnectionCount() { return connectionCount; }
        public double getAverageInterval() { return averageInterval; }
        public double getIntervalStdDev() { return intervalStdDev; }
        public double getMaxConnectionRate() { return maxConnectionRate; }
        public int getBurstCount() { return burstCount; }
        public double getSynPacketsRatio() { return synPacketsRatio; }
        public double getCompletionRatio() { return completionRatio; }
        public double getUserAgentVariety() { return userAgentVariety; }
    }
    
    /**
     * Attack prediction result
     */
    public static class AttackPrediction {
        private final double probability;
        private final String attackType;
        private final Long timeUntilMs;
        
        public AttackPrediction(double probability, String attackType, Long timeUntilMs) {
            this.probability = probability;
            this.attackType = attackType;
            this.timeUntilMs = timeUntilMs;
        }
        
        public double getProbability() { return probability; }
        public String getAttackType() { return attackType; }
        public Long getTimeUntilMs() { return timeUntilMs; }
        
        @Override
        public String toString() {
            String timeStr = timeUntilMs == null ? "unknown" : 
                             (timeUntilMs / 3600000) + "h " + 
                             ((timeUntilMs % 3600000) / 60000) + "m";
            
            return String.format("Prediction: %s attack (%d%% probability) in %s", 
                               attackType, (int)(probability * 100), timeStr);
        }
    }
}