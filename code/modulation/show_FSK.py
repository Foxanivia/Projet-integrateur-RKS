# Bibliothèque
import numpy as np
import matplotlib.pyplot as plt


class ModulateurFSK:
    def __init__(self, debit_binaire, frequence0, frequence1, amplitude):
        """
        Initialise le modulateur FSK avec les paramètres spécifiés.

        :param debit_binaire: Débit binaire (bps)
        :param frequence0: Fréquence pour le bit 0 (Hz)
        :param frequence1: Fréquence pour le bit 1 (Hz)
        :param amplitude: Amplitude du signal
        """
        self.debit_binaire = debit_binaire
        self.f0 = frequence0
        self.f1 = frequence1
        self.amp = amplitude

        # Définit un taux d'échantillonnage suffisamment élevé (Nyquist-Shannon)
        self.taux_echantillonnage = 100 * max(frequence0, frequence1)

    def moduler(self, sequence_bits):
        """
        Module une séquence de bits en utilisant FSK.
        :param sequence_bits: Séquence de bits à moduler
        :return: Signal modulé
        """
        duree_bit = 1 / self.debit_binaire
        t = np.arange(0, duree_bit, 1 / self.taux_echantillonnage)
        signal = np.array([])

        for bit in sequence_bits:
            if bit == 0:
                porteuse = self.amp * np.cos(2 * np.pi * self.f0 * t)
            else:
                porteuse = self.amp * np.cos(2 * np.pi * self.f1 * t)
            signal = np.concatenate((signal, porteuse))

        return signal

    def visualiser(self, sequence_bits):
        """
        Visualise le signal modulé FSK pour une séquence de bits donnée.
        :param sequence_bits: Séquence de bits à moduler
        """
        signal = self.moduler(sequence_bits)
        t = np.arange(0, len(signal)) / self.taux_echantillonnage
        plt.figure(figsize=(10, 6))
        plt.plot(t, signal)
        plt.title('Modulation FSK de la séquence binaire')
        plt.xlabel('Temps (s)')
        plt.ylabel('Amplitude (V)')
        plt.grid()
        plt.show()


def main():
    ###################################
    # Exemple pour modulation visible #
    ###################################

    debit_binaire = 100                              # En réalité: 5 à 20 kbps
    frequence0 = 1000                                # En réalité: Environ 315 MHz ou 433 MHz
    frequence1 = frequence0+1000                     # En réalité: ~ 20 kHz. de différence après la fréquence porteuse
    amplitude = 1
    sequence_bits = np.random.randint(0, 2, 10)      # Séquence de 10 bits aléatoire

    modulateur = ModulateurFSK(debit_binaire, frequence0, frequence1, amplitude)
    modulateur.visualiser(sequence_bits)


if __name__ == "__main__":
    main()
