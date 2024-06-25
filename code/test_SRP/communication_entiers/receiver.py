import time
from rpi_rf import RFDevice

# Configuration des broches GPIO
GPIO_PIN = 27

# Initialisation de l'appareil RF
rfdevice = RFDevice(GPIO_PIN)
rfdevice.enable_rx()

def receive_integer():
    timestamp = None
    while True:
        if rfdevice.rx_code_timestamp != timestamp:
            timestamp = rfdevice.rx_code_timestamp
            integer = rfdevice.rx_code
            print(f"Entier reçu: {integer}")
        time.sleep(1)

try:
    print("En attente de messages...")
    receive_integer()
except KeyboardInterrupt:
    print("Programme interrompu.")
finally:
    rfdevice.cleanup()