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
    def __init__(self):
        super().__init__()
        self.cond = {}
        self.strings = {}

    def matches(self, items):
        variable = items[0]
        string = items[1]
        self.strings[variable] = string
        return json.loads('{{"{}": {}}}'.format(variable, string))

    def or_cond(self, items):
        return items

    def and_cond(self, items):
        return items

    def stmt(self, items):
        return items

    def parenthesis(self, items):
        return items

    def terminal(self, items):
        return items

    def condition(self, items):
        return items

    def rule(self, items):
        return items

    def start(self, items):
        return items


class Interpreter:
    def __init__(self, rules_file, ir_file):
        # Prendi il nome del file delle regole, del binario in VEX e della grammatica
        self.rules_file = os.path.abspath(rules_file)
        self.ir_file = ir_file
        self.grammar_path = Path(".").parent
        # Elementi utili per la valutazione della condizione
        self.tokens = ['and', 'or', '(', ')']
        self.high = ['and']
        self.low = ['or']

    # Divido tra stringhe e condizione
    def __check_conditions(self, transformed_tree):
        matches = []
        conditions = []
        rule_name = transformed_tree[0]
        for el in transformed_tree[1]:
            if isinstance(el, dict):
                matches.append(el)  # Stringhe
            elif isinstance(el, list):
                conditions = el[0]  # Condizioni
        d = self.__flat_dictionary(matches)  # Appiattisco il risultato in un'unica lista di stringhe da matchare
        self.__search_conditions(conditions, d, rule_name)  # Cerco le condizioni nel VEX

    def __priority(self, op1, op2):
        if (op1 == '(' or op1 == ')') or (op2 == '(' or op2 == ')'):
            return -1
        if op1 in self.high and op2 in self.high:
            return 0
        if op1 in self.low and op2 in self.low:
            return 0
        if op1 in self.high and op2 in self.low:
            return 1
        if op1 in self.low and op2 in self.high:
            return -1

    # Da lista che rappresenta la condizione infissa a postfissa
    def __postfix(self, infix):
        op_stack = []
        postfix = []
        for el in infix:
            if el in self.tokens:
                if not op_stack:
                    op_stack.append(el)
                    continue
                if self.__priority(op_stack[-1], el) >= 0:
                    postfix.append(op_stack.pop())
                    op_stack.append(el)
                elif self.__priority(op_stack[-1], el) < 0:
                    if el == ')':
                        postfix.append(op_stack.pop())
                    else:
                        op_stack.append(el)
            else:
                postfix.append(el)
        while op_stack:
            if op_stack[-1] == '(':
                op_stack.pop()
            else:
                postfix.append(op_stack.pop())
        return postfix

    # Verifico che la singola stringa sia presente nel VEX
    def __find(self, d, element):
        imarks = []  # Lista degli indirizzi delle istruzioni da stampare
        found = False
        with open(self.ir_file, 'r') as ir:
            for line in ir:
                # Normalizzo i valori esadecimali nel VEX e nelle stringe da verificare
                # Es: 0x0000000000000034 diventa 0x34
                hex_line = re.findall(r"0x[0-9a-f]+", line, re.I)
                if hex_line:
                    number = hex(int(hex_line[0], 0))
                    line = line.replace(hex_line[0], number)

                hex_cond = re.findall(r"0x[0-9a-f]+", d[element], re.I)
                if hex_cond:
                    d[element] = d[element].replace(hex_cond[0], hex(int(hex_cond[0], 0)))
                # Ricerco l'indirizzo da appendere alla lista
                mark = re.findall(r"^    00 | -+ IMark\(0x[0-9a-f]+, [0-9], [0-9]\) -+", line, re.I)
                if mark:
                    imarks.append(mark)
                # Verifico la presenza della stringa in presenza di wildcard
                if "??" in d[element]:
                    wildcard = 1
                    instruction = re.split("\\?\\?", d[element])
                    for ins in instruction:
                        if ins not in line:
                            wildcard = 0
                            break
                    if wildcard:
                        address = ''.join(re.findall(r"0x[0-9a-f]+", ''.join(imarks.pop()), re.I))
                        print('Condition ${} = "{}" is satisfied for the istruction'
                              ' at address: {} with instruction "{}"'.format(element, d[element], address,
                                                                             line.strip().split("| ")[1]))
                        found = True
                        return found
                # Se non siamo in presenza di wildcard verifico normalelmente la presenza
                if d[element] in line:
                    address = ''.join(re.findall(r"0x[0-9a-f]+", ''.join(imarks.pop()), re.I))
                    print('Condition ${} = "{}" is satisfied for the istruction'
                          ' at address: {}'.format(element, d[element], address))
                    found = True
                    return found
            # Se ho terminato il VEX e non ho trovato nessun match
            if not found:
                print('Condition ${} = "{}" is not satisfied'.format(element, d[element]))
                found = False
                return found

    # Valutazione della condizione
    def evaluate(self, postfix, d):
        stack = []
        # Scorro l'espressione e verifico se si tratta di un operatore o un operando
        for element in postfix:
            if element in self.tokens:  # Operatore
                val2 = stack.pop()
                val1 = stack.pop()
                if element == 'and':
                    stack.append(val1 and val2)
                if element == 'or':
                    stack.append(val1 or val2)
            else:  # Operando
                # Metto nello stack True o False, a seconda che la stringa sia presente o meno nel binario liftato
                stack.append(self.__find(d, element))
        return stack[0]  # Il risultato finale della valutazione sta sempre nella posizione 0

    # Da lista di liste di elementi a un'unica lista di elementi in rappresentazione infissa
    def __infix(self, conditions):
        result = []
        if isinstance(conditions, (list, tuple)):
            for x in conditions:
                result.extend(self.__infix(x))
        else:
            result.append(conditions)
        return result

    # Verifico che la condizione sia presente tra le stringhe e se lo è verifico che la stringa esista nel codice VEX
    def __search_conditions(self, conditions, d, rule_name):
        condition = conditions[0]
        # Se la condizione non è composta
        if len(conditions) == 1:
            if self.__find(d, condition):
                print("The condition ${} from rule: {} is satisfied".format(condition, rule_name))
            else:
                print("The condition ${} from rule: {} is not satisfied".format(condition, rule_name))

        # Se la condizione è composta
        else:
            # Utilizzo la reverse polish notation per la valutazione della condizione
            infix = self.__infix(conditions)
            # Da lista a stringa della condizione infissa
            cond = ''.join("$" + val + " " if val not in self.tokens else val + " " for val in infix).strip()
            postfix = self.__postfix(infix)
            # Verifico che la condizione sia soddisfatta
            if self.evaluate(postfix, d):
                print("The condition {} from rule: {} is satisfied".format(cond.strip(), rule_name))
            else:
                print("The condition {} from rule: {} is not satisfied".format(cond.strip(), rule_name))

    def __flat_dictionary(self, matches):
        d = {}
        for dictionary in matches:
            d.update(dictionary)
        return d

    def interprets(self):
        # Crea il parser utilizzando la grammatica
        parser = lark.Lark.open(self.grammar_path / 'grammar.lark', rel_to=__file__, parser='lalr',
                                postlex=TreeIndenter(), transformer=MyTransformer())
        # Leggi il contenuto delle regole
        with open(self.rules_file, 'r') as f:
            data = f.read()
            '''
            Parserizza il file delle regole e crea l'AST che viene trasformato in una formato più gestibile dalla classe
            MyTransformer
            '''
            transformed_tree = parser.parse(data)
        # Distinzione tra file di regole con una o più regole
        if isinstance(transformed_tree[0], str):
            self.__check_conditions(transformed_tree)  # Una regola
        else:
            for tree in transformed_tree:
                self.__check_conditions(tree)  # Più regole


def main():
    x = Interpreter("rule1.txt", "/tmp/ir-8a10eb94-4e39-11ed-8129-beab88cf32ef")
    x.interprets()


if __name__ == '__main__':
    main()
