package id.neonddos;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.scheduler.BukkitRunnable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

// Ganti imports dari javax.mail.* ke jakarta.mail.*
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

/**
 * Sistem untuk mengirimkan notifikasi melalui berbagai channel
 * (in-game, Discord, email)
 */
public class NotificationSystem {

    private final neonddos plugin;
    private final Logger logger;
    
    // Konfigurasi notifikasi
    private boolean enableIngameNotifications;
    private boolean enableDiscordWebhook;
    private boolean enableEmailAlerts;
    private int notificationLevel;
    
    // Discord settings
    private String discordWebhookUrl;
    private String discordUsername;
    private String discordAvatarUrl;
    
    // Email settings
    private String emailSmtpHost;
    private int emailSmtpPort;
    private boolean emailSmtpAuth;
    private boolean emailSmtpStartTLS;
    private String emailUsername;
    private String emailPassword;
    private String emailFrom;
    private String emailRecipients;
    
    // Mengelola riwayat notifikasi untuk mencegah spam
    private final List<String> recentNotifications = new ArrayList<>();
    private static final int NOTIFICATION_COOLDOWN = 60000; // 1 menit dalam ms
    
    public NotificationSystem(neonddos plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        
        // Load konfigurasi
        loadConfiguration();
        
        // Mulai task untuk membersihkan notifikasi lama
        startCleanupTask();
        
        logger.info("Sistem notifikasi diinisialisasi");
    }
    
    /**
     * Inisialisasi dan muat konfigurasi
     */
    private void loadConfiguration() {
        FileConfiguration config = plugin.getConfig();
        
        // PERBAIKAN: Tambahkan logging untuk memverifikasi webhook URL
        discordWebhookUrl = config.getString("notifications.discord.webhookUrl", "");
        if (discordWebhookUrl.isEmpty()) {
            logger.warning("Discord webhook URL tidak dikonfigurasi atau kosong");
        } else {
            logger.info("Discord webhook URL dikonfigurasi: " + discordWebhookUrl.substring(0, 30) + "...");
        }
        
        // Tambahkan logging untuk username dan avatar
        discordUsername = config.getString("notifications.discord.username", "NeonDDoS Alert");
        discordAvatarUrl = config.getString("notifications.discord.avatarUrl", "");
        
        enableDiscordWebhook = config.getBoolean("notifications.discord.enabled", false);
        logger.info("Notifikasi Discord " + (enableDiscordWebhook ? "diaktifkan" : "dinonaktifkan"));
        
        // Konfigurasi umum
        enableIngameNotifications = config.getBoolean("notifications.ingame.enabled", true);
        enableEmailAlerts = config.getBoolean("notifications.email.enabled", false);
        notificationLevel = config.getInt("notifications.level", 2);
        
        // Konfigurasi email
        emailSmtpHost = config.getString("notifications.email.smtp.host", "smtp.gmail.com");
        emailSmtpPort = config.getInt("notifications.email.smtp.port", 587);
        emailSmtpAuth = config.getBoolean("notifications.email.smtp.auth", true);
        emailSmtpStartTLS = config.getBoolean("notifications.email.smtp.startTLS", true);
        emailUsername = config.getString("notifications.email.username", "");
        emailPassword = config.getString("notifications.email.password", "");
        emailFrom = config.getString("notifications.email.from", "");
        emailRecipients = config.getString("notifications.email.recipients", "");
        
        logger.info("Konfigurasi notifikasi dimuat: " +
                   "ingame=" + enableIngameNotifications + ", " +
                   "discord=" + enableDiscordWebhook + ", " +
                   "email=" + enableEmailAlerts);
    }
    
    /**
     * Mulai task untuk membersihkan notifikasi lama
     */
    private void startCleanupTask() {
        new BukkitRunnable() {
            @Override
            public void run() {
                long now = System.currentTimeMillis();
                synchronized (recentNotifications) {
                    recentNotifications.clear();
                }
            }
        }.runTaskTimerAsynchronously(plugin, 20 * 60, 20 * 60); // Berjalan setiap 1 menit
    }
    
    /**
     * Kirim notifikasi serangan DDoS terdeteksi
     */
    public void sendAttackNotification(String ip, int attackScore, String attackType) {
        // Buat ID unik untuk notifikasi ini
        String notificationId = ip + "_" + attackType + "_" + System.currentTimeMillis();
        
        // Cek apakah notifikasi serupa sudah dikirim baru-baru ini
        if (hasRecentlySentSimilarNotification(notificationId)) {
            return;
        }
        
        // Format pesan
        String message = String.format("§c[NeonDDoS] §4ALERT: §cSerangan %s terdeteksi dari IP %s (skor: %d)", 
                attackType, ip, attackScore);
        
        // Kirim notifikasi melalui berbagai channel
        if (enableIngameNotifications) {
            sendIngameNotification(message, attackScore);
        }
        
        if (enableDiscordWebhook && attackScore >= getMinScoreForDiscord()) {
            sendDiscordNotification(ip, attackScore, attackType);
        }
        
        if (enableEmailAlerts && attackScore >= getMinScoreForEmail()) {
            sendEmailAlert(ip, attackScore, attackType);
        }
        
        // Catat ID notifikasi untuk mencegah spam
        markNotificationAsSent(notificationId);
    }
    
    /**
     * Kirim notifikasi dalam game ke admin
     */
    private void sendIngameNotification(String message, int attackScore) {
        // Kirim notifikasi dalam game hanya jika levelnya cukup tinggi
        if (attackScore < 50 && notificationLevel < 3) {
            return; // Skip notifikasi minor jika level rendah
        }
        
        new BukkitRunnable() {
            @Override
            public void run() {
                for (Player player : Bukkit.getOnlinePlayers()) {
                    if (player.hasPermission("neonddos.admin") || player.isOp()) {
                        player.sendMessage(message);
                    }
                }
                
                // Log ke console juga
                logger.warning(ChatColor.stripColor(message));
            }
        }.runTask(plugin);
    }
    
    /**
     * Kirim webhook ke Discord
     */
    private void sendDiscordNotification(String ip, int attackScore, String attackType) {
        if (!enableDiscordWebhook) {
            // PERBAIKAN: Log alasan tidak mengirim
            logger.fine("Notifikasi Discord tidak dikirim: fitur dinonaktifkan");
            return;
        }
        
        if (discordWebhookUrl == null || discordWebhookUrl.isEmpty()) {
            logger.warning("Discord webhook URL tidak dikonfigurasi");
            return;
        }
        
        // PERBAIKAN: Log sebelum mencoba mengirim
        logger.info("Mencoba mengirim notifikasi Discord untuk IP " + ip);
        
        new BukkitRunnable() {
            @Override
            public void run() {
                try {
                    // Build JSON content
                    String jsonContent = buildDiscordWebhookJson(ip, attackScore, attackType);
                    
                    // PERBAIKAN: Log JSON untuk debugging
                    logger.fine("Discord webhook payload: " + jsonContent);
                    
                    // Kirim HTTP request
                    URL url = new URL(discordWebhookUrl);
                    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                    connection.setRequestMethod("POST");
                    connection.setRequestProperty("Content-Type", "application/json");
                    connection.setDoOutput(true);
                    
                    try (OutputStream os = connection.getOutputStream()) {
                        byte[] input = jsonContent.getBytes("utf-8");
                        os.write(input, 0, input.length);
                    }
                    
                    // Baca response
                    int responseCode = connection.getResponseCode();
                    if (responseCode == HttpURLConnection.HTTP_OK || 
                        responseCode == HttpURLConnection.HTTP_NO_CONTENT) {
                        logger.info("Notifikasi Discord terkirim sukses");
                    } else {
                        try (BufferedReader br = new BufferedReader(
                            new InputStreamReader(connection.getErrorStream() != null ? 
                                                connection.getErrorStream() : 
                                                connection.getInputStream(), "utf-8"))) {
                            StringBuilder response = new StringBuilder();
                            String responseLine;
                            while ((responseLine = br.readLine()) != null) {
                                response.append(responseLine.trim());
                            }
                            logger.warning("Gagal mengirim webhook Discord: " + 
                                          responseCode + " " + response.toString());
                        }
                    }
                    
                    connection.disconnect();
                } catch (Exception e) {
                    // PERBAIKAN: Tangkap semua exception, bukan hanya IOException
                    logger.warning("Error mengirim notifikasi Discord: " + e.getClass().getName() + ": " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }.runTaskAsynchronously(plugin);
    }
    
    /**
     * Build JSON untuk webhook Discord
     */
    private String buildDiscordWebhookJson(String ip, int attackScore, String attackType) {
        String serverName = Bukkit.getServer().getName();
        if (serverName == null || serverName.isEmpty()) {
            serverName = "Minecraft Server";
        }
        
        String colorHex = getColorForSeverity(attackScore);
        
        // PERBAIKAN: Escape karakter yang mungkin rusak JSON
        serverName = escapeJsonString(serverName);
        attackType = escapeJsonString(attackType);
        ip = escapeJsonString(ip);
        
        return "{"
            + "\"username\":\"" + escapeJsonString(discordUsername) + "\","
            + "\"avatar_url\":\"" + escapeJsonString(discordAvatarUrl) + "\","
            + "\"embeds\":["
            + "  {"
            + "    \"title\":\"⚠️ Serangan DDoS Terdeteksi\","
            + "    \"color\":" + colorHex + ","
            + "    \"description\":\"Serangan **" + attackType + "** terdeteksi pada server.\","
            + "    \"fields\":["
            + "      {\"name\":\"IP Penyerang\",\"value\":\"" + ip + "\",\"inline\":true},"
            + "      {\"name\":\"Skor Tingkat Keparahan\",\"value\":\"" + attackScore + "\",\"inline\":true},"
            + "      {\"name\":\"Server\",\"value\":\"" + serverName + "\",\"inline\":true}"
            + "    ],"
            + "    \"footer\":{\"text\":\"NeonDDoS Protection System\"}"
            + "  }"
            + "]"
            + "}";
    }
    
    /**
     * Helper method untuk escape string di JSON
     */
    private String escapeJsonString(String input) {
        if (input == null) return "";
        return input.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t");
    }
    
    /**
     * Mengirim email alert
     */
    private void sendEmailAlert(String ip, int attackScore, String attackType) {
        if (emailUsername.isEmpty() || emailPassword.isEmpty() || emailRecipients.isEmpty()) {
            logger.warning("Konfigurasi email tidak lengkap");
            return;
        }
        
        new BukkitRunnable() {
            @Override
            public void run() {
                try {
                    // Konfigurasi properti email
                    Properties properties = new Properties();
                    properties.put("mail.smtp.auth", String.valueOf(emailSmtpAuth));
                    properties.put("mail.smtp.starttls.enable", String.valueOf(emailSmtpStartTLS));
                    properties.put("mail.smtp.host", emailSmtpHost);
                    properties.put("mail.smtp.port", String.valueOf(emailSmtpPort));
                    
                    // Buat session email
                    Session session = Session.getInstance(properties, 
                        new jakarta.mail.Authenticator() { // Update ini juga ke jakarta
                            protected jakarta.mail.PasswordAuthentication getPasswordAuthentication() { // Update ini juga ke jakarta
                                return new jakarta.mail.PasswordAuthentication(emailUsername, emailPassword); // Update ini juga ke jakarta
                            }
                        });
                    
                    // Buat pesan email
                    Message message = new MimeMessage(session);
                    message.setFrom(new InternetAddress(emailFrom.isEmpty() ? emailUsername : emailFrom));
                    
                    // Set penerima
                    for (String recipient : emailRecipients.split(",")) {
                        message.addRecipient(Message.RecipientType.TO, new InternetAddress(recipient.trim()));
                    }
                    
                    // Subjek dan isi email
                    String serverName = Bukkit.getServer().getName();
                    if (serverName.isEmpty()) {
                        serverName = "Minecraft Server";
                    }
                    
                    message.setSubject("[NeonDDoS Alert] Serangan DDoS pada " + serverName);
                    message.setText(
                        "PERINGATAN KEAMANAN: Serangan DDoS terdeteksi\n\n" +
                        "Detail Serangan:\n" +
                        "- Server: " + serverName + "\n" +
                        "- IP Penyerang: " + ip + "\n" +
                        "- Tipe Serangan: " + attackType + "\n" +
                        "- Skor Serangan: " + attackScore + "\n" +
                        "- Waktu: " + new Date().toString() + "\n\n" +
                        "IP ini telah otomatis diblokir oleh sistem NeonDDoS Protection.\n" +
                        "Mohon periksa log server untuk informasi lebih lanjut.\n\n" +
                        "-- \n" +
                        "NeonDDoS Protection System"
                    );
                    
                    // Kirim email
                    Transport.send(message);
                    logger.info("Email alert berhasil dikirim");
                } catch (MessagingException e) {
                    logger.log(Level.WARNING, "Gagal mengirim email alert", e);
                }
            }
        }.runTaskAsynchronously(plugin);
    }
    
    /**
     * Mendapatkan minimum skor untuk Discord notification
     */
    private int getMinScoreForDiscord() {
        switch (notificationLevel) {
            case 1: return 150;  // Hanya notifikasi serangan besar
            case 2: return 100;  // Notifikasi serangan sedang-besar
            case 3: return 50;   // Notifikasi semua serangan
            default: return 100; // Default - notifikasi sedang-besar
        }
    }
    
    /**
     * Mendapatkan minimum skor untuk Email alert
     */
    private int getMinScoreForEmail() {
        switch (notificationLevel) {
            case 1: return 200;  // Hanya email untuk serangan sangat besar
            case 2: return 150;  // Email untuk serangan besar
            case 3: return 100;  // Email untuk serangan sedang-besar
            default: return 150; // Default - email untuk serangan besar
        }
    }
    
    /**
     * Mendapatkan warna hex berdasarkan tingkat keparahan (untuk Discord)
     */
    private String getColorForSeverity(int attackScore) {
        if (attackScore >= 200) {
            return "15158332"; // Merah tua (hex: #e74c3c)
        } else if (attackScore >= 150) {
            return "15105570"; // Merah (hex: #e67e22)
        } else if (attackScore >= 100) {
            return "16776960"; // Kuning (hex: #ffff00)
        } else {
            return "5793266"; // Oranye (hex: #f1c40f)
        }
    }
    
    /**
     * Cek apakah notifikasi serupa sudah dikirim baru-baru ini
     */
    private boolean hasRecentlySentSimilarNotification(String notificationId) {
        synchronized (recentNotifications) {
            for (String recent : recentNotifications) {
                // Cek kesamaan IP dan jenis serangan
                String[] parts = recent.split("_");
                String[] newParts = notificationId.split("_");
                
                if (parts.length >= 2 && newParts.length >= 2 && 
                    parts[0].equals(newParts[0]) && parts[1].equals(newParts[1])) {
                    
                    // Cek waktunya
                    if (parts.length >= 3 && newParts.length >= 3) {
                        try {
                            long oldTime = Long.parseLong(parts[2]);
                            long newTime = Long.parseLong(newParts[2]);
                            
                            if (newTime - oldTime < NOTIFICATION_COOLDOWN) {
                                return true; // Masih dalam cooldown
                            }
                        } catch (NumberFormatException e) {
                            // Abaikan error parsing
                        }
                    }
                }
            }
        }
        return false;
    }
    
    /**
     * Tandai bahwa notifikasi sudah dikirim
     */
    private void markNotificationAsSent(String notificationId) {
        synchronized (recentNotifications) {
            recentNotifications.add(notificationId);
            
            // Batasi ukuran list
            while (recentNotifications.size() > 100) {
                recentNotifications.remove(0);
            }
        }
    }
    
    /**
     * Kirim notifikasi informasi umum ke admin
     */
    public void sendInfoNotification(String message) {
        if (enableIngameNotifications) {
            new BukkitRunnable() {
                @Override
                public void run() {
                    for (Player player : Bukkit.getOnlinePlayers()) {
                        if (player.hasPermission("neonddos.admin") || player.isOp()) {
                            player.sendMessage("§b[NeonDDoS] §3INFO: §b" + message);
                        }
                    }
                }
            }.runTask(plugin);
        }
        
        logger.info(message);
    }
    
    /**
     * Enable/disable notifikasi in-game
     */
    public void setEnableIngameNotifications(boolean enable) {
        this.enableIngameNotifications = enable;
    }
    
    /**
     * Enable/disable Discord webhook
     */
    public void setEnableDiscordWebhook(boolean enable) {
        this.enableDiscordWebhook = enable;
    }
    
    /**
     * Enable/disable email alerts
     */
    public void setEnableEmailAlerts(boolean enable) {
        this.enableEmailAlerts = enable;
    }
    
    /**
     * Set level notifikasi (1=minimal, 3=detail)
     */
    public void setNotificationLevel(int level) {
        this.notificationLevel = Math.max(1, Math.min(3, level));
    }
    
    /**
     * Muat ulang konfigurasi notifikasi
     */
    public void reloadConfiguration() {
        loadConfiguration();
    }
}