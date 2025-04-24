package id.neonddos;

import org.bukkit.Bukkit;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Kelas untuk mengelola interaksi dengan firewall sistem operasi
 */
public class FirewallManager {

    private final neonddos plugin;
    private final Logger logger;
    private final String osName;
    private final boolean isWindows;
    private final boolean isLinux;
    private final boolean isMac;
    
    // Daftar IP yang diblokir oleh firewall
    private final Set<String> blockedIps;
    
    // Daftar IP yang dimasukkan dalam whitelist
    private final Set<String> whitelistedIps;
    
    // Status apakah firewall dapat diakses
    private boolean firewallAccessible;
    
    // File whitelist
    private File whitelistFile;
    private FileConfiguration whitelistConfig;
    
    // Konfigurasi
    private boolean useSystemFirewall;
    private boolean notifyOnFailure;
    private int maxBlockedIps;

    public FirewallManager(neonddos plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.osName = System.getProperty("os.name").toLowerCase();
        this.isWindows = osName.contains("win");
        this.isLinux = osName.contains("nix") || osName.contains("nux") || osName.contains("aix");
        this.isMac = osName.contains("mac");
        
        this.blockedIps = Collections.newSetFromMap(new ConcurrentHashMap<>());
        this.whitelistedIps = Collections.newSetFromMap(new ConcurrentHashMap<>());
        
        // Muat konfigurasi
        loadConfiguration();
        
        // Inisialisasi whitelist
        loadWhitelist();
        
        // Cek akses ke firewall
        checkFirewallAccess();
        
        // Bersihkan aturan lama jika diperlukan
        if (firewallAccessible && plugin.getConfig().getBoolean("firewall.cleanupOnStartup", true)) {
            cleanupOldRules();
        }
        
        logger.info("FirewallManager diinisialisasi - " + 
                    (firewallAccessible ? "Firewall sistem dapat diakses" : "Firewall sistem TIDAK dapat diakses"));
    }
    
    /**
     * Muat konfigurasi dari config.yml
     */
    private void loadConfiguration() {
        FileConfiguration config = plugin.getConfig();
        
        useSystemFirewall = config.getBoolean("firewall.useSystemFirewall", false);
        notifyOnFailure = config.getBoolean("firewall.notifyOnFailure", true);
        maxBlockedIps = config.getInt("firewall.maxBlockedIps", 1000);
        
        if (!useSystemFirewall) {
            logger.info("Penggunaan firewall sistem dinonaktifkan dalam konfigurasi");
        }
    }
    
    /**
     * Memeriksa apakah plugin memiliki akses ke firewall
     */
    private void checkFirewallAccess() {
        if (!useSystemFirewall) {
            firewallAccessible = false;
            return;
        }
        
        try {
            if (isWindows) {
                // Cek apakah plugin berjalan dengan priviledge admin
                Process process = Runtime.getRuntime().exec("netsh advfirewall show currentprofile");
                int exitCode = process.waitFor();
                firewallAccessible = (exitCode == 0);
            } else if (isLinux) {
                // Cek apakah iptables tersedia
                Process process = Runtime.getRuntime().exec("which iptables");
                int exitCode = process.waitFor();
                firewallAccessible = (exitCode == 0);
                
                if (firewallAccessible) {
                    // Cek apakah kita punya priviledge untuk menjalankannya
                    process = Runtime.getRuntime().exec("iptables -L");
                    exitCode = process.waitFor();
                    firewallAccessible = (exitCode == 0);
                }
            } else if (isMac) {
                // Cek apakah pfctl tersedia
                Process process = Runtime.getRuntime().exec("which pfctl");
                int exitCode = process.waitFor();
                firewallAccessible = (exitCode == 0);
            } else {
                logger.warning("OS tidak dikenali, fitur firewall sistem tidak tersedia");
                firewallAccessible = false;
            }
        } catch (IOException | InterruptedException e) {
            logger.warning("Gagal mengakses firewall sistem: " + e.getMessage());
            firewallAccessible = false;
        }
    }
    
    /**
     * Muat daftar whitelist dari file
     */
    private void loadWhitelist() {
        try {
            whitelistFile = new File(plugin.getDataFolder(), "whitelist.yml");
            
            if (!whitelistFile.exists()) {
                plugin.saveResource("whitelist.yml", false);
            }
            
            whitelistConfig = YamlConfiguration.loadConfiguration(whitelistFile);
            List<String> ips = whitelistConfig.getStringList("whitelisted-ips");
            whitelistedIps.addAll(ips);
            
            logger.info("Whitelist firewall dimuat: " + whitelistedIps.size() + " IP dalam daftar");
        } catch (Exception e) {
            logger.warning("Gagal memuat whitelist: " + e.getMessage());
        }
    }
    
    /**
     * Simpan whitelist ke file
     */
    private void saveWhitelist() {
        try {
            whitelistConfig.set("whitelisted-ips", new ArrayList<>(whitelistedIps));
            whitelistConfig.save(whitelistFile);
        } catch (IOException e) {
            logger.warning("Gagal menyimpan whitelist: " + e.getMessage());
        }
    }
    
    /**
     * Bersihkan aturan firewall lama
     */
    private void cleanupOldRules() {
        logger.info("Membersihkan aturan firewall lama...");
        try {
            if (isWindows) {
                // Hapus semua aturan yang dibuat oleh plugin
                Process process = Runtime.getRuntime().exec(
                    "netsh advfirewall firewall delete rule name=\"NeonDDoS Block\""
                );
                process.waitFor();
            } else if (isLinux) {
                // Bersihkan chain khusus jika ada
                Process process = Runtime.getRuntime().exec(
                    "iptables -D INPUT -j NEONDDOS >/dev/null 2>&1 || true"
                );
                process.waitFor();
                
                process = Runtime.getRuntime().exec(
                    "iptables -F NEONDDOS >/dev/null 2>&1 || true"
                );
                process.waitFor();
                
                process = Runtime.getRuntime().exec(
                    "iptables -X NEONDDOS >/dev/null 2>&1 || true"
                );
                process.waitFor();
                
                // Buat chain baru
                process = Runtime.getRuntime().exec("iptables -N NEONDDOS");
                process.waitFor();
                
                process = Runtime.getRuntime().exec("iptables -I INPUT -j NEONDDOS");
                process.waitFor();
            } else if (isMac) {
                // MacOS menggunakan pfctl, implementasikan jika diperlukan
            }
            logger.info("Pembersihan aturan firewall lama selesai");
        } catch (IOException | InterruptedException e) {
            logger.warning("Gagal membersihkan aturan firewall lama: " + e.getMessage());
        }
    }
    
    /**
     * Blokir IP di firewall sistem
     */
    public boolean blockIpInFirewall(String ip) {
        if (!firewallAccessible || !useSystemFirewall) {
            return false;
        }
        
        // Jangan blokir IP yang masuk whitelist
        if (isWhitelisted(ip)) {
            logger.info("IP " + ip + " tidak diblokir karena ada dalam whitelist");
            return false;
        }
        
        // Cek reputasi IP
        AnalyticsSystem analyticsSystem = plugin.getAnalyticsSystem();
        if (analyticsSystem != null) {
            AnalyticsSystem.IpReputation reputation = analyticsSystem.getIpReputation(ip);
            
            // Jika IP ini sering false positive, berikan peringatan
            if (reputation.getFalsePositiveCount() > 2) {
                logger.warning("IP " + ip + " memiliki " + reputation.getFalsePositiveCount() + 
                               " false positives sebelumnya, pertimbangkan untuk whitelist");
            }
        }
        
        // Cek apakah sudah diblokir
        if (blockedIps.contains(ip)) {
            return true;
        }
        
        // Cek maksimal IP yang diblokir
        if (blockedIps.size() >= maxBlockedIps) {
            logger.warning("Jumlah maksimum IP yang diblokir tercapai (" + maxBlockedIps + ")");
            return false;
        }
        
        try {
            boolean success = false;
            
            if (isWindows) {
                // Windows Firewall
                String command = "netsh advfirewall firewall add rule name=\"NeonDDoS Block " + ip + 
                                "\" dir=in interface=any action=block remoteip=" + ip;
                Process process = Runtime.getRuntime().exec(command);
                int exitCode = process.waitFor();
                success = (exitCode == 0);
            } else if (isLinux) {
                // Linux iptables
                String command = "iptables -A NEONDDOS -s " + ip + " -j DROP";
                Process process = Runtime.getRuntime().exec(command);
                int exitCode = process.waitFor();
                success = (exitCode == 0);
            } else if (isMac) {
                // MacOS pfctl
                // Implementasi untuk MacOS jika diperlukan
            }
            
            if (success) {
                blockedIps.add(ip);
                logger.info("IP " + ip + " berhasil diblokir di firewall sistem");
                return true;
            } else {
                logger.warning("Gagal memblokir IP " + ip + " di firewall sistem");
                return false;
            }
        } catch (IOException | InterruptedException e) {
            logger.warning("Error saat memblokir IP " + ip + ": " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Lepaskan blokir IP di firewall sistem
     */
    public boolean unblockIpFromFirewall(String ip) {
        if (!firewallAccessible || !useSystemFirewall) {
            return false;
        }
        
        // Cek apakah IP diblokir
        if (!blockedIps.contains(ip)) {
            return true;
        }
        
        try {
            boolean success = false;
            
            if (isWindows) {
                // Windows Firewall
                String command = "netsh advfirewall firewall delete rule name=\"NeonDDoS Block " + ip + "\"";
                Process process = Runtime.getRuntime().exec(command);
                int exitCode = process.waitFor();
                success = (exitCode == 0);
            } else if (isLinux) {
                // Linux iptables
                String command = "iptables -D NEONDDOS -s " + ip + " -j DROP";
                Process process = Runtime.getRuntime().exec(command);
                int exitCode = process.waitFor();
                success = (exitCode == 0);
            } else if (isMac) {
                // MacOS pfctl
                // Implementasi untuk MacOS jika diperlukan
            }
            
            if (success) {
                blockedIps.remove(ip);
                logger.info("IP " + ip + " berhasil dilepaskan dari blokir di firewall sistem");
                return true;
            } else {
                logger.warning("Gagal melepaskan blokir IP " + ip + " di firewall sistem");
                return false;
            }
        } catch (IOException | InterruptedException e) {
            logger.warning("Error saat melepaskan blokir IP " + ip + ": " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Tambahkan IP ke whitelist
     */
    public void addToWhitelist(String ip) {
        if (isValidIp(ip)) {
            whitelistedIps.add(ip);
            saveWhitelist();
            logger.info("IP " + ip + " ditambahkan ke whitelist");
            
            // Jika IP sedang diblokir, lepaskan blokirnya
            if (blockedIps.contains(ip)) {
                unblockIpFromFirewall(ip);
            }
        } else {
            logger.warning("Format IP tidak valid: " + ip);
        }
    }
    
    /**
     * Hapus IP dari whitelist
     */
    public void removeFromWhitelist(String ip) {
        if (whitelistedIps.remove(ip)) {
            saveWhitelist();
            logger.info("IP " + ip + " dihapus dari whitelist");
        }
    }
    
    /**
     * Cek apakah IP ada dalam whitelist
     */
    public boolean isWhitelisted(String ip) {
        return whitelistedIps.contains(ip);
    }
    
    /**
     * Validasi format IP address
     */
    private boolean isValidIp(String ip) {
        String[] octets = ip.split("\\.");
        if (octets.length != 4) {
            return false;
        }
        
        for (String octet : octets) {
            try {
                int value = Integer.parseInt(octet);
                if (value < 0 || value > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Mendapatkan daftar IP yang diblokir
     */
    public Set<String> getBlockedIps() {
        return new HashSet<>(blockedIps);
    }
    
    /**
     * Mendapatkan daftar IP dalam whitelist
     */
    public Set<String> getWhitelistedIps() {
        return new HashSet<>(whitelistedIps);
    }
    
    /**
     * Cek apakah firewall dapat diakses
     */
    public boolean isFirewallAccessible() {
        return firewallAccessible;
    }
    
    /**
     * Mendapatkan deskripsi status firewall
     */
    public Map<String, Object> getFirewallStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("accessible", firewallAccessible);
        status.put("osType", getOsType());
        status.put("blockedCount", blockedIps.size());
        status.put("whitelistCount", whitelistedIps.size());
        status.put("enabled", useSystemFirewall);
        return status;
    }
    
    /**
     * Dapatkan tipe OS
     */
    private String getOsType() {
        if (isWindows) return "Windows";
        if (isLinux) return "Linux";
        if (isMac) return "MacOS";
        return "Unknown";
    }
    
    /**
     * Bersihkan semua aturan saat plugin dinonaktifkan
     */
    public void cleanup() {
        if (firewallAccessible && useSystemFirewall) {
            logger.info("Membersihkan aturan firewall saat shutdown...");
            cleanupOldRules();
        }
    }
}