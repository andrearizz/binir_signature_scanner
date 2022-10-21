import angr
import os
import sys
import uuid


def next_key(d, key):
    keys = iter(d)
    key in keys  # Terribile ma efficace
    return next(keys, sys.maxsize)


class Lifter:
    def __init__(self, binary, function='', start_addr=0, end_addr=0):
        self.binary = os.path.abspath(binary)

        # Carica il binario
        self.proj = angr.Project(binary, load_options={'auto_load_libs': False})

        # Prendi il control flow graph
        self.cfg = self.proj.analyses.CFGFast()

        self.function = function
        self.start_addr = start_addr
        self.end_addr = end_addr
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

        # Flat basic blocks
        basic_blocks = [item for sublist in basic_blocks for item in sublist]
        basic_blocks.sort()
        # La lista di ritorno è composta dagli indirizzi di inizio di ogni basic block
        return basic_blocks

    def __function_bb(self):
        basic_blocks = []
        for addr in self.functions_addr:
            if self.functions_addr[addr].name == self.function:
                basic_blocks.append(list(self.functions_addr[addr].block_addrs_set))
        # Flat basic blocks
        basic_blocks = [item for sublist in basic_blocks for item in sublist]
        basic_blocks.sort()
        # La lista di ritorno è composta dagli indirizzi di inizio di ogni basic block
        return basic_blocks

    def __range_bb(self):
        basic_blocks = []
        start = int(self.start_addr)
        end = int(self.end_addr)
        for addr in self.functions_addr:
            next_addr = next_key(self.functions_addr._function_map, addr)
            if int(addr <= start < next_addr or start <= addr <= end):
                basic_blocks.append(list(self.functions_addr[addr].block_addrs_set))
        # Flat basic blocks
        basic_blocks = [item for sublist in basic_blocks for item in sublist]
        basic_blocks.sort()
        # La lista di ritorno è composta dagli indirizzi di inizio di ogni basic block
        return basic_blocks

    def __addr_bb(self):
        basic_blocks = []
        start = int(self.start_addr)
        print(hex(start))
        for addr in self.functions_addr:
            next_addr = next_key(self.functions_addr._function_map, addr)
            if int(addr <= start < next_addr or addr >= start):
                basic_blocks.append(list(self.functions_addr[addr].block_addrs_set))
        # Flat basic blocks
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

        if self.function:
            irsbs = self.__irsb(self.__function_bb())
        elif self.start_addr and self.end_addr:
            irsbs = self.__irsb(self.__range_bb())
        elif self.start_addr and not self.end_addr:
            irsbs = self.__irsb(self.__addr_bb())
        else:
            # Ottieni tutti i basic block
            irsbs = self.__irsb(self.__all_bb())

        for ir in irsbs:
            with open(filename, "a") as sys.stdout:  # Redirigi lo standard output verso il file temporaneo
                ir.pp()
        # Resetta lo standard output
        sys.stdout = sys.__stdout__
        return filename


def main():
    lifter = Lifter("server", start_addr=0x500024, end_addr=0x500036)
    print(lifter.lift())


if __name__ == '__main__':
    main()
