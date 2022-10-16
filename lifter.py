import angr
import os
import sys
import uuid


class Lifter:
    def __init__(self, binary):
        self.binary = os.path.abspath(binary)

        # Carica il binario
        self.proj = angr.Project(binary, load_options={'auto_load_libs': False})

        # Prendi il control flow graph
        self.cfg = self.proj.analyses.CFGFast()

        '''
        Oggetto accessibile come dizionario contenente l'indirizzo e il nome delle funzioni del binario. 
        Iterabile attraverso l'indirizzo delle funzioni (vedi __all_bb())
        '''
        self.functions_addr = self.cfg.kb.functions

    # Ottieni tutti i basic block del binario
    def __all_bb(self):
        basic_blocks = []
        for addr in self.functions_addr:
            basic_blocks.append(list(self.functions_addr[addr].block_addrs_set))

        # Flat basic_blocks
        basic_blocks = [item for sublist in basic_blocks for item in sublist]
        basic_blocks.sort()
        # La lista di ritorno è composta dagli indirizzi di inizio di ogni basic block
        return basic_blocks

    # Ottieni la lista di ogni basic block in VEX
    def __irsb(self, basic_blocks):
        irsbs = []
        for block in basic_blocks:
            irsbs.append(self.proj.factory.block(block).vex)
        # print(irsbs)
        return irsbs

    def lift(self):
        # Crea un file temporaneo in cui scrivere il codice in VEX
        uid = uuid.uuid1()
        filename = "/tmp/ir-{}".format(uid)

        # Ottieni tutti i basic block
        irsbs = self.__irsb(self.__all_bb())
        for ir in irsbs:
            with open(filename, "a") as sys.stdout:  # Redirigi lo standard output verso il file temporaneo
                ir.pp()
        # Resetta lo standard output
        sys.stdout = sys.__stdout__
        return filename


def main():
    lifter = Lifter("server")
    print(lifter.lift())


if __name__ == '__main__':
    main()
