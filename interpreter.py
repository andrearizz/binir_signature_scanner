import lark
from lark.indenter import Indenter
from lark import Transformer
from pathlib import Path
import os
import re
import json


# Classe usata da Lark per gestire l'indentazione
class TreeIndenter(Indenter):
    NL_type = '_NL'
    OPEN_PAREN_types = []
    CLOSE_PAREN_types = []
    INDENT_type = '_INDENT'
    DEDENT_type = '_DEDENT'
    tab_len = 8


# Classe usata da Lark per trasformare l'albero sintattico astratto in un formato più gestibile al fine di valutarlo
class MyTransformer(Transformer):
    def matches(self, items):
        variable = items[0]
        string = items[1]
        s = '{{"{}": {}}}'.format(variable, string)
        return s

    def condition(self, items):
        cond = items[0]
        return "Condition: {}".format(cond)

    def stmt(self, items):
        return items

    def rule(self, items):
        return items


class Interpreter:
    def __init__(self, rules_file, ir_file):
        # Prendi il nome del file delle regole, del binario in VEX e della grammatica
        self.rules_file = os.path.abspath(rules_file)
        self.ir_file = os.path.abspath(ir_file)
        self.grammar_path = Path(".").parent

    def interprets(self):
        # Crea il parser utilizzando la grammatica
        parser = lark.Lark.open(self.grammar_path / 'grammar.lark', rel_to=__file__, parser='lalr',
                                postlex=TreeIndenter(), transformer=MyTransformer())
        # print(parser.parse(test_tree).pretty())
        # Leggi il contenuto delle regole
        with open(self.rules_file, 'r') as f:
            data = f.read()
            '''
            Parserizza il file delle regole e crea l'AST che viene trasformato in una formato più gestibile dalla classe
            MyTransformer
            '''
            transformed_tree = parser.parse(data)
        # print("Rule name = {}".format(transformed_tree[0]))
        # print(transformed_tree[1])
        matches = []
        conditions = []

        # Separa le stringhe da matchare con le condizioni

        for stmt in transformed_tree[1]:
            if stmt.startswith('Condition'):
                split = re.split('Condition: ', stmt)
                conditions.append(split[1].strip())
            else:
                matches.append(json.loads(stmt))

        # print(matches)
        # print(conditions)
        '''
        Ho deciso di rappresentare le stringhe da matchare come lista di dizionari. Le stringhe:
        $x = "PUT(rdx) = 0x0000000000000000"
        $y = "PUT(rax) = 0x0000000000000002"
        $z = "PUT(offset=184) = 0x00000000004012f4"
        
        saranno rappresentate come:
        [{'x': 'PUT(rdx) = 0x0000000000000000'}, 
        {'y': 'PUT(rax) = 0x0000000000000002'}, 
        {'z': 'PUT(offset=184) = 0x00000000004012f4'}]
        
        E le condizioni come lista di condizioni. Per questa prima versione ho previsto solo condizioni del tipo
        "esiste". Ad esempio, per verificare che la condizione $x = "PUT(rdx) = 0x00000000004012f4" sia verificata,
         nello statement condition della regola basta inserire $x.
        
        La rappresentazione a dizionario mi permette di verificare facilmente la presenza di una stringa. 
        '''

        # Appiattisco la lista di dizionari in un unico dizionario
        d = {}
        for dictionary in matches:
            d.update(dictionary)
        # print(d)
        with open(self.ir_file, 'r') as ir:
            vex = ir.read()
        # Verifico che la condizione sia presente tra le stringhe e se lo è verifico che la stringa esista nel codice VEX
        for condition in conditions:
            if condition in d:
                string = d[condition]
                if string in vex:
                    print("Found the string {}".format(string))
                    break


def main():
    x = Interpreter("rule1.txt", "/tmp/ir-140810f4-4c8a-11ed-a348-beab88cf32f0")
    x.interprets()


if __name__ == '__main__':
    main()
