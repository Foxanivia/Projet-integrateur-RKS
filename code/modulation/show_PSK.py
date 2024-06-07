# Bibliothèque
import numpy as np
import matplotlib.pyplot as plt


class ModulateurPSK:
    def __init__(self, frequence_port, debit_binaire, phase0, phase1, amplitude):
        """
        Initialise le modulateur PSK avec les paramètres spécifiés.
        :param frequence_port: Fréquence de la porteuse (Hz)
        :param debit_binaire: Débit binaire (bps)
        :param phase0: Phase pour le bit 0 (radians)
        :param phase1: Phase pour le bit 1 (radians)
        :param amplitude: Amplitude du signal
        """
        self.frequence_port = frequence_port
        self.debit_binaire = debit_binaire
        self.phase0 = phase0
        self.phase1 = phase1
        self.amplitude = amplitude
        self.taux_echantillonnage = 100 * self.frequence_port  # Taux d'échantillonnage suffisamment élevé

    def moduler(self, sequence_bits):
        """
        Module une séquence de bits en utilisant PSK.

        :param sequence_bits: Séquence de bits à moduler
        :return: Signal modulé
        """
        duree_bit = 1 / self.debit_binaire
        t = np.arange(0, duree_bit, 1 / self.taux_echantillonnage)
        signal = np.array([])

        for bit in sequence_bits:
            if bit == 0:
                porteuse = self.amplitude * np.cos(2 * np.pi * self.frequence_port * t + self.phase0)
            else:
                porteuse = self.amplitude * np.cos(2 * np.pi * self.frequence_port * t + self.phase1)
            signal = np.concatenate((signal, porteuse))

        return signal

    def visualiser(self, sequence_bits):
        """
        Visualise le signal modulé PSK pour une séquence de bits donnée.
        :param sequence_bits: Séquence de bits à moduler
        """
        signal = self.moduler(sequence_bits)
        t = np.arange(0, len(signal)) / self.taux_echantillonnage
        plt.figure(figsize=(10, 6))
        plt.plot(t, signal)
        plt.title('Modulation PSK de la séquence binaire')
        plt.xlabel('Temps (s)')
        plt.ylabel('Amplitude (V)')
        plt.grid()
        plt.show()


def main():
    ###################################
    # Exemple pour modulation visible #
    ###################################

    frequence_port = 1000                          # En réalité: 315 MHz ou 433 MHz
    debit_binaire = 100                            # En réalité: 5 à 20 kbps
    phase0 = 0
    phase1 = np.pi
    amplitude = 1
    sequence_bits = np.random.randint(0, 2, 10)    # Séquence de 10 bits aléatoire

    modulateur = ModulateurPSK(frequence_port, debit_binaire, phase0, phase1, amplitude)
    modulateur.visualiser(sequence_bits)


if __name__ == "__main__":
    main()
