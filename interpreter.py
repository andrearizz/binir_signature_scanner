import lark
from lark.indenter import Indenter
from lark import Transformer
from pathlib import Path
import os
import re
import json
from collections.abc import MutableMapping


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
        self.id_or = -1
        self.id_and = -1
        self.flag = 0

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

    def __check_conditions(self, transformed_tree):
        matches = []
        conditions = []
        rule_name = transformed_tree[0]
        # print(transformed_tree)
        for el in transformed_tree[1]:
            # print(el)
            if isinstance(el, dict):
                matches.append(el)
            elif isinstance(el, list):
                conditions = el[0]
        # print('m', matches)
        # print('c', conditions)

        d = self.__flat_dictionary(matches)
        self.__search_conditions(conditions, d, rule_name)

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

    def evaluate(self, postfix, d):
        stack = []
        for element in postfix:
            if element in self.tokens:
                val2 = stack.pop()
                val1 = stack.pop()
                if element == 'and':
                    stack.append(val1 and val2)
                if element == 'or':
                    stack.append(val1 or val2)
            else:
                imarks = []
                found = 0
                with open(self.ir_file, 'r') as ir:
                    for line in ir:
                        mark = re.findall(r"^    00 | -+ IMark\(0x[0-9A-F]+, [0-9], [0-9]\) -+", line, re.I)
                        if mark:
                            imarks.append(mark)
                        if "??" in d[element]:
                            wildcard = 1
                            instruction = re.split("\\?\\?", d[element])
                            for ins in instruction:
                                if ins not in line:
                                    wildcard = 0
                                    break
                            if wildcard:
                                address = ''.join(re.findall(r"0x[0-9A-F]+", ''.join(imarks.pop()), re.I))
                                print('Condition ${} = "{}" is satisfied for the istruction'
                                      ' at address: {} with instruction "{}"'.format(element, d[element], address,
                                                                                   line.strip().split("| ")[1]))
                                found = 1
                                stack.append(True)
                        if d[element] in line:
                            address = ''.join(re.findall(r"0x[0-9A-F]+", ''.join(imarks.pop()), re.I))
                            print('Condition ${} = "{}" is satisfied for the istruction'
                                  ' at address: {}'.format(element, d[element], address))
                            found = 1
                            stack.append(True)
                    if not found:
                        stack.append(False)
                        print('Condition ${} = "{}" is not satisfied'.format(element, d[element]))
        return stack[0]

    def infix(self, conditions):
        result = []
        if isinstance(conditions, (list, tuple)):
            for x in conditions:
                result.extend(self.infix(x))
        else:
            result.append(conditions)
        return result

    def __search_conditions(self, conditions, d, rule_name):
        # Verifico che la condizione sia presente tra le stringhe e se lo è verifico che la stringa esista nel codice
        # VEX
        condition = conditions[0]
        # print(conditions)
        if len(conditions) == 1:
            # print(condition)
            found = 0
            imarks = []
            if condition in d:
                string = d[condition]
                with open(self.ir_file, 'r') as ir:
                    for line in ir:
                        mark = re.findall(r"^    00 | -+ IMark\(0x[0-9A-F]+, [0-9], [0-9]\) -+", line, re.I)
                        if mark:
                            imarks.append(mark)
                        if string in line:
                            address = ''.join(re.findall(r"0x[0-9A-F]+", ''.join(imarks.pop()), re.I))
                            print("The condition ${} for the rule {} is satisfied for the"
                                  " istruction at address {}".format(condition, rule_name, address))
                            found = 1
                            break
                    if not found:
                        print('The condition ${} = "{}" for the rule {} is not satisfied'.format(condition, string,
                                                                                                 rule_name))

        else:
            # infix = [y for x in conditions for y in (x if isinstance(x, list) else [x])]
            infix = self.infix(conditions)
            cond = ''.join("$" + val + " " if val not in self.tokens else val + " " for val in infix).strip()
            postfix = self.__postfix(infix)
            if self.evaluate(postfix, d):
                print("The condition {} from rule: {} is satisfied".format(cond.strip(), rule_name))
            else:
                print("The condition {} from rule: {} is not satisfied".format(cond.strip(), rule_name))

        '''
        for condition in conditions:
            if condition in d:
                string = d[condition]
                if string in self.vex:
                    print("Found the string {}".format(string))
        '''

    def __flat_dictionary(self, matches):
        d = {}
        for dictionary in matches:
            d.update(dictionary)
        return d

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
            # print(transformed_tree)

        # print(transformed_tree.pretty())
        # print(transformed_tree[0])

        if isinstance(transformed_tree[0], str):
            self.__check_conditions(transformed_tree)
        else:
            for tree in transformed_tree:
                self.__check_conditions(tree)

                # print(conditions)
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
                # d = self.__flat_dictionary(matches)
                # self.__search_conditions(conditions, d)


def main():
    x = Interpreter("rule1.txt", "/tmp/ir-8a10eb94-4e39-11ed-8129-beab88cf32ef")
    x.interprets()


if __name__ == '__main__':
    main()
