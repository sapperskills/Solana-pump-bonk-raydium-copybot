import time
import threading
import psutil
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Pump.fun coin livestream link
PUMP_URL = "https://pump.fun/coin/7L6M32mpkewGWj8bHspoX8QDe9pb3b3S1U33KpFvpump"

# Updated JS: Waits for Privy to load, then logs in
INJECT_JS = """
(function() {
    const checkPrivy = setInterval(() => {
        if (typeof PrivyClient !== 'undefined') {
            clearInterval(checkPrivy);
            const script = document.createElement('script');
            script.innerHTML = `
                (async () => {
                    try {
                        const client = new PrivyClient({
                            embeddedWallets: true,
                            loginMethods: ['wallet'],
                            appearance: { theme: 'dark' },
                            clientId: "client-WY5brZnRUhFQnX6ip6yRzypC9WLtB9j8mFnq4cyPBMq8W"
                        });
                        await client.login();
                        console.log("✅ Burner wallet logged in.");
                    } catch (err) {
                        console.error("❌ Login failed:", err);
                    }
                })();
            `;
            document.body.appendChild(script);
        }
    }, 500);

    const loadScript = document.createElement('script');
    loadScript.src = "https://auth.privy.io/js/privy.js";
    document.head.appendChild(loadScript);
})();
"""

# Function to throttle CPU priority of a process
def throttle_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.nice(psutil.IDLE_PRIORITY_CLASS if os.name == "nt" else 19)
    except Exception as e:
        print(f"⚠️ Could not throttle process: {e}")

# Launch a lightweight Chrome instance and inject login JS
def open_burner_session(index):
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--mute-audio")
    chrome_options.add_argument("--blink-settings=imagesEnabled=false")
    chrome_options.add_argument("--disable-background-networking")
    chrome_options.add_argument("--disable-sync")
    chrome_options.add_argument("--metrics-recording-only")
    chrome_options.add_argument("--disable-default-apps")
    chrome_options.add_argument("--disable-translate")
    chrome_options.add_argument("--disable-notifications")
    chrome_options.add_argument("--disable-background-timer-throttling")
    chrome_options.add_argument("--disable-hang-monitor")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-infobars")
    chrome_options.add_argument("--window-size=800,600")

    driver = webdriver.Chrome(options=chrome_options)
    throttle_process(driver.service.process.pid)

    try:
        driver.get(PUMP_URL)
        print(f"[{index}] Opened pump.fun stream.")
        time.sleep(5)  # Let the page and scripts load

        driver.execute_script(INJECT_JS)
        print(f"[{index}] Privy login script injected.")

        # Keep tab alive (simulate presence)
        while True:
            time.sleep(60)

    except Exception as e:
        print(f"[{index}] Error: {e}")

# Main entry
if __name__ == "__main__":
    NUM_SESSIONS = 20  # Adjust this number as needed

    threads = []
    for i in range(NUM_SESSIONS):
        t = threading.Thread(target=open_burner_session, args=(i,))
        t.start()
        threads.append(t)
        time.sleep(1.5)  # Stagger startup to avoid CPU spike

    for t in threads:
        t.join()
