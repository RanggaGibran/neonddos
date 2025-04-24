package id.neonddos;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;

/**
 * Sistem filter berdasarkan lokasi geografis
 */
public class GeoIPFilter {
    
    private final neonddos plugin;
    private final Logger logger;
    
    // Database file
    private File geoConfigFile;
    private FileConfiguration geoConfig;
    
    // Daftar negara yang diblok/diizinkan
    private final Set<String> blockedCountries;
    private final Set<String> allowedCountries;
    
    // Mode operasi
    private boolean enableGeoFiltering = false;
    private boolean whitelistMode = false; // false = blacklist mode (block specific), true = whitelist mode (allow specific)
    
    public GeoIPFilter(neonddos plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        
        this.blockedCountries = new HashSet<>();
        this.allowedCountries = new HashSet<>();
        
        // Load konfigurasi
        loadConfiguration();
        
        logger.info("GeoIP Filter diinisialisasi - Mode: " + 
                   (enableGeoFiltering ? (whitelistMode ? "Whitelist" : "Blacklist") : "Disabled"));
    }
    
    private void loadConfiguration() {
        // Load dari config.yml utama dulu
        FileConfiguration config = plugin.getConfig();
        enableGeoFiltering = config.getBoolean("geoip.enabled", false);
        whitelistMode = config.getBoolean("geoip.whitelist-mode", false);
        
        // Load file konfigurasi geolocation terpisah
        geoConfigFile = new File(plugin.getDataFolder(), "geoip.yml");
        
        if (!geoConfigFile.exists()) {
            try {
                geoConfigFile.createNewFile();
                geoConfig = YamlConfiguration.loadConfiguration(geoConfigFile);
                
                // Set default values
                List<String> defaultBlockedCountries = new ArrayList<>();
                defaultBlockedCountries.add("A1"); // Anonymous Proxy
                defaultBlockedCountries.add("A2"); // Satellite Provider
                
                List<String> defaultAllowedCountries = new ArrayList<>();
                defaultAllowedCountries.add("ID"); // Indonesia
                defaultAllowedCountries.add("US"); // United States
                defaultAllowedCountries.add("SG"); // Singapore
                
                geoConfig.set("blocked-countries", defaultBlockedCountries);
                geoConfig.set("allowed-countries", defaultAllowedCountries);
                
                geoConfig.save(geoConfigFile);
            } catch (IOException e) {
                logger.warning("Gagal membuat file geoip.yml: " + e.getMessage());
                return;
            }
        } else {
            geoConfig = YamlConfiguration.loadConfiguration(geoConfigFile);
        }
        
        // Load daftar negara
        blockedCountries.clear();
        allowedCountries.clear();
        
        List<String> blockedList = geoConfig.getStringList("blocked-countries");
        List<String> allowedList = geoConfig.getStringList("allowed-countries");
        
        blockedCountries.addAll(blockedList);
        allowedCountries.addAll(allowedList);
        
        logger.info("GeoIP Filter: " + blockedCountries.size() + " negara diblok, " + 
                   allowedCountries.size() + " negara diizinkan");
    }
    
    /**
     * Memeriksa apakah IP diizinkan berdasarkan GeoIP
     * @return true jika diizinkan, false jika harus diblok
     */
    public boolean isAllowedByGeoIP(InetAddress address) {
        if (!enableGeoFiltering) {
            return true; // Filter tidak aktif, izinkan semua
        }
        
        String countryCode = lookupCountry(address);
        
        // Jika lookup gagal, gunakan kebijakan default
        if (countryCode == null || countryCode.isEmpty()) {
            return !whitelistMode; // Di mode whitelist, blokir jika tidak dikenal
        }
        
        if (whitelistMode) {
            // Whitelist mode: hanya izinkan negara dalam daftar
            return allowedCountries.contains(countryCode);
        } else {
            // Blacklist mode: tolak negara dalam daftar blok
            return !blockedCountries.contains(countryCode);
        }
    }
    
    /**
     * Lookup kode negara dari IP address
     * Gunakan library GeoIP atau layanan API
     */
    private String lookupCountry(InetAddress address) {
        // Implementasi lookup GeoIP sesungguhnya akan menggunakan 
        // database seperti MaxMind GeoIP atau layanan API
        
        // Untuk prototype sementara, kita buat simulasi sederhana
        String ip = address.getHostAddress();
        
        // Contoh: IP lokal sebagai Indonesia
        if (ip.startsWith("127.") || ip.startsWith("192.168.") || 
            ip.startsWith("10.") || ip.startsWith("172.16.")) {
            return "ID";
        }
        
        // Simulasikan beberapa IP untuk demo
        if (ip.startsWith("1.1.")) return "CN"; // China
        if (ip.startsWith("8.8.")) return "US"; // USA
        if (ip.startsWith("5.5.")) return "RU"; // Russia
        
        // Default: Unknown
        return "XX";
    }
    
    /**
     * Update daftar negara yang diblok
     */
    public void updateBlockedCountries(List<String> countries) {
        blockedCountries.clear();
        blockedCountries.addAll(countries);
        
        // Simpan ke file
        geoConfig.set("blocked-countries", new ArrayList<>(blockedCountries));
        try {
            geoConfig.save(geoConfigFile);
        } catch (IOException e) {
            logger.warning("Gagal menyimpan daftar negara yang diblok: " + e.getMessage());
        }
    }
    
    /**
     * Update daftar negara yang diizinkan
     */
    public void updateAllowedCountries(List<String> countries) {
        allowedCountries.clear();
        allowedCountries.addAll(countries);
        
        // Simpan ke file
        geoConfig.set("allowed-countries", new ArrayList<>(allowedCountries));
        try {
            geoConfig.save(geoConfigFile);
        } catch (IOException e) {
            logger.warning("Gagal menyimpan daftar negara yang diizinkan: " + e.getMessage());
        }
    }
    
    /**
     * Mengatur mode operasi filter
     */
    public void setFilterMode(boolean enabled, boolean whitelistMode) {
        this.enableGeoFiltering = enabled;
        this.whitelistMode = whitelistMode;
        
        // Update config.yml
        FileConfiguration config = plugin.getConfig();
        config.set("geoip.enabled", enabled);
        config.set("geoip.whitelist-mode", whitelistMode);
        plugin.saveConfig();
        
        logger.info("GeoIP Filter mode diubah: " + 
                   (enableGeoFiltering ? (whitelistMode ? "Whitelist" : "Blacklist") : "Disabled"));
    }
    
    /**
     * Mendapatkan daftar negara yang diblok
     */
    public Set<String> getBlockedCountries() {
        return new HashSet<>(blockedCountries);
    }
    
    /**
     * Mendapatkan daftar negara yang diizinkan
     */
    public Set<String> getAllowedCountries() {
        return new HashSet<>(allowedCountries);
    }
    
    /**
     * Apakah filter GeoIP aktif
     */
    public boolean isEnabled() {
        return enableGeoFiltering;
    }
    
    /**
     * Apakah dalam mode whitelist
     */
    public boolean isWhitelistMode() {
        return whitelistMode;
    }
}