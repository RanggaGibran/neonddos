package id.neonddos;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerLoginEvent;
import org.bukkit.event.server.ServerListPingEvent;
import org.bukkit.event.player.PlayerJoinEvent;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Kelas yang bertanggung jawab untuk memantau dan menganalisis koneksi ke server
 */
public class ConnectionMonitor implements Listener {

    private final neonddos plugin;
    private final Logger logger;
    
    // Menyimpan timestamp koneksi berdasarkan IP
    private final Map<String, ArrayDeque<Long>> connectionHistory;
    // Menyimpan jumlah koneksi saat ini per IP
    private final Map<String, Integer> connectionCount;
    // Menyimpan IP yang diblokir sementara
    private final Map<String, Long> temporaryBlocklist;
    
    // Konfigurasi
    private int connectionThreshold = 10; // Maksimal koneksi dalam timeWindow
    private long timeWindow = 10000; // Jendela waktu dalam ms (10 detik)
    private long blockDuration = 60000; // Durasi blokir dalam ms (60 detik)
    
    public ConnectionMonitor(neonddos plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.connectionHistory = new ConcurrentHashMap<>();
        this.connectionCount = new ConcurrentHashMap<>();
        this.temporaryBlocklist = new ConcurrentHashMap<>();
        
        // Mulai task untuk membersihkan data lama
        startCleanupTask();
        
        logger.info("Sistem monitoring koneksi telah diinisialisasi");
    }

    /**
     * Mulai task untuk membersihkan data koneksi lama secara berkala
     */
    private void startCleanupTask() {
        Bukkit.getScheduler().runTaskTimerAsynchronously(plugin, () -> {
            long now = System.currentTimeMillis();
            
            // Bersihkan data koneksi lama
            connectionHistory.forEach((ip, timestamps) -> {
                timestamps.removeIf(time -> (now - time) > timeWindow);
                if (timestamps.isEmpty()) {
                    connectionHistory.remove(ip);
                    connectionCount.remove(ip);
                }
            });
            
            // Hapus IP dari blocklist jika sudah melewati durasi blokir
            temporaryBlocklist.entrySet().removeIf(entry -> (now - entry.getValue()) > blockDuration);
            
        }, 20L * 10, 20L * 10); // Jalankan setiap 10 detik
    }

    /**
     * Mencatat dan menganalisis koneksi baru ke server
     */
    public boolean recordConnection(InetAddress address) {
        String ip = address.getHostAddress();
        long currentTime = System.currentTimeMillis();
        
        // Cek apakah IP diblokir sementara
        if (isTemporarilyBlocked(ip)) {
            return false;
        }
        
        // Check dengan TrafficPrioritizer dulu
        TrafficPrioritizer trafficPrioritizer = plugin.getTrafficPrioritizer();
        if (trafficPrioritizer != null && 
                !trafficPrioritizer.processConnection(address, TrafficPrioritizer.ConnectionType.SERVER_PING)) {
            return false;
        }
        
        // Check dengan GeoIPFilter jika ada
        GeoIPFilter geoIPFilter = plugin.getGeoIPFilter();
        if (geoIPFilter != null && geoIPFilter.isEnabled() && !geoIPFilter.isAllowedByGeoIP(address)) {
            return false;
        }
        
        // Catat koneksi baru
        connectionHistory.computeIfAbsent(ip, k -> new ArrayDeque<>()).add(currentTime);
        connectionCount.put(ip, connectionCount.getOrDefault(ip, 0) + 1);
        
        // Analisis pola koneksi
        if (isConnectionSuspicious(ip)) {
            handleSuspiciousConnection(ip);
            return false;
        }
        
        return true;
    }
    
    /**
     * Memeriksa apakah koneksi mencurigakan berdasarkan frekuensi
     */
    private boolean isConnectionSuspicious(String ip) {
        Queue<Long> history = connectionHistory.get(ip);
        if (history == null) return false;
        
        int recentConnections = history.size();
        return recentConnections > connectionThreshold;
    }
    
    /**
     * Menangani koneksi mencurigakan
     */
    private void handleSuspiciousConnection(String ip) {
        logger.warning("Koneksi mencurigakan terdeteksi dari IP: " + ip);
        temporaryBlocklist.put(ip, System.currentTimeMillis());
        logger.info("IP " + ip + " telah diblokir sementara selama " + (blockDuration / 1000) + " detik");
    }
    
    /**
     * Memeriksa apakah IP diblokir sementara
     */
    public boolean isTemporarilyBlocked(String ip) {
        Long blockTime = temporaryBlocklist.get(ip);
        if (blockTime == null) return false;
        
        return (System.currentTimeMillis() - blockTime) <= blockDuration;
    }
    
    /**
     * Event handler untuk login player
     */
    @EventHandler
    public void onPlayerLogin(PlayerLoginEvent event) {
        InetAddress address = event.getAddress();
        
        // Check dengan TrafficPrioritizer dulu untuk login
        TrafficPrioritizer trafficPrioritizer = plugin.getTrafficPrioritizer();
        if (trafficPrioritizer != null && 
                !trafficPrioritizer.processConnection(address, TrafficPrioritizer.ConnectionType.PLAYER_LOGIN)) {
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER, 
                    "§cKoneksi kamu dibatasi karena server sedang dalam tekanan tinggi.\n§eCoba lagi dalam beberapa saat.");
            logger.info("Menolak login dari " + address.getHostAddress() + " karena prioritas traffic");
            return;
        }
        
        // Existing connection monitoring logic
        if (!recordConnection(address)) {
            event.disallow(PlayerLoginEvent.Result.KICK_OTHER, 
                    "§cKoneksi kamu dibatasi karena terlalu banyak percobaan koneksi.\n§eCoba lagi dalam beberapa saat.");
            logger.info("Menolak koneksi dari " + address.getHostAddress() + " karena mencurigakan");
        }
        
        // Kirim data ke DdosDetector jika tersedia
        if (plugin.getDdosDetector() != null) {
            plugin.getDdosDetector().recordConnection(address, 0, DdosDetector.ConnectionType.PLAYER_LOGIN);
        }
    }
    
    /**
     * Event handler untuk ping server
     */
    @EventHandler
    public void onServerListPing(ServerListPingEvent event) {
        InetAddress address = event.getAddress();
        recordConnection(address);
        
        // Kirim data ke DdosDetector jika tersedia
        if (plugin.getDdosDetector() != null) {
            plugin.getDdosDetector().recordConnection(address, 0, DdosDetector.ConnectionType.SERVER_PING);
        }
    }
    
    /**
     * Event handler untuk player join
     */
    @EventHandler
    public void onPlayerJoin(PlayerJoinEvent event) {
        // Kirim data ke DdosDetector jika tersedia
        if (plugin.getDdosDetector() != null) {
            InetAddress address = event.getPlayer().getAddress().getAddress();
            plugin.getDdosDetector().recordConnection(address, 0, DdosDetector.ConnectionType.PLAYER_JOIN);
        }
    }
    
    /**
     * Mengatur threshold koneksi
     */
    public void setConnectionThreshold(int threshold) {
        this.connectionThreshold = threshold;
    }
    
    /**
     * Mengatur jendela waktu (dalam ms)
     */
    public void setTimeWindow(long timeWindow) {
        this.timeWindow = timeWindow;
    }
    
    /**
     * Mengatur durasi blokir (dalam ms)
     */
    public void setBlockDuration(long blockDuration) {
        this.blockDuration = blockDuration;
    }
    
    /**
     * Mendapatkan statistik koneksi terkini
     */
    public Map<String, Integer> getCurrentConnections() {
        Map<String, Integer> result = new HashMap<>();
        
        for (Player player : Bukkit.getOnlinePlayers()) {
            String ip = player.getAddress().getAddress().getHostAddress();
            result.put(ip, result.getOrDefault(ip, 0) + 1);
        }
        
        return result;
    }
}