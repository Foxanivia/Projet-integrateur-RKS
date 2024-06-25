import time
from rpi_rf import RFDevice

# Configuration des broches GPIO
GPIO_PIN = 17

# Initialisation de l'appareil RF
rfdevice = RFDevice(GPIO_PIN)
rfdevice.enable_tx()

PULSE_LENGTH = 350

def send_integer(integer):
    rfdevice.tx_code(integer, tx_pulselength=PULSE_LENGTH)
    time.sleep(0.1)

try:
    while True:
        integer = int(input("Entrez l'entier à envoyer : "))
        send_integer(integer)
        print(f"Entier '{integer}' envoyé.")
except KeyboardInterrupt:
    print("Programme interrompu.")
finally:
    rfdevice.cleanup()