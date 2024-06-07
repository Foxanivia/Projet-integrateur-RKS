# Bibliothèque
import numpy as np
import matplotlib.pyplot as plt


class ModulateurASK:
    def __init__(self, f_porteuse: int, debit_binaire: int, amplitude0: int, amplitude1: int):
        """
        Initialise le modulateur ASK avec les paramètres spécifiés.
        :param f_porteuse: Fréquence de la porteuse (Hz)
        :param debit_binaire: Débit binaire (bps)
        :param amplitude0: Amplitude pour le bit 0
        :param amplitude1: Amplitude pour le bit 1
        """
        self.f_porteuse = f_porteuse
        self.debit_binaire = debit_binaire
        self.amp0 = amplitude0
        self.amp1 = amplitude1

        # Définit un taux d'échantillonnage suffisamment élevé (Nyquist-Shannon)
        self.t_echantillon = 100 * self.f_porteuse

    def moduler(self, sequence_bits: list):
        """
        Module une séquence de bits en utilisant ASK.
        :param sequence_bits: Séquence de bits à moduler
        :return: Signal modulé
        """
        duree_bit = 1 / self.debit_binaire
        t = np.arange(0, duree_bit, 1 / self.t_echantillon)
        signal = np.array([])

        for bit in sequence_bits:
            if bit == 0:
                porteuse = self.amp0 * np.cos(2 * np.pi * self.f_porteuse * t)
            else:
                porteuse = self.amp1 * np.cos(2 * np.pi * self.f_porteuse * t)
            signal = np.concatenate((signal, porteuse))

        return signal

    def visualiser(self, bits_seq: list):
        """
        Visualise le signal modulé ASK pour une séquence de bits donnée.
        :param bits_seq: Séquence de bits à moduler
        """
        signal = self.moduler(bits_seq)
        t = np.arange(0, len(signal)) / self.t_echantillon

        # Plot
        plt.figure(figsize=(10, 6))
        plt.plot(t, signal)
        plt.title('Modulation ASK de la séquence binaire')
        plt.xlabel('Temps (s)')
        plt.ylabel('Amplitude (V)')
        plt.grid()
        plt.show()


def main():
    ###################################
    # Exemple pour modulation visible #
    ###################################

    f_porteue = 1000                         # En réalité: 315 MHz ou 433 MHz
    debit_binaire = 100                      # En réalité: 5 à 20 kbps
    amplitude0 = 1                           # En réalité, les amplitudes dépendent de la puissance/distance du signal
    amplitude1 = 2
    bits_seq = np.random.randint(0, 2, 10)   # Séquence de 10 bits aléatoire

    modulateur = ModulateurASK(f_porteue, debit_binaire, amplitude0, amplitude1)
    modulateur.visualiser(bits_seq)


if __name__ == "__main__":
    main()
