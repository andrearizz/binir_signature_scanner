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
        '''
        self.id_or = self.id_or + 1
        if self.cond:
            for key in items[1]:
                self.cond[f"or_{self.id_or}"] = items[0] + '-' + key
                return self.cond
        else:
            self.cond[f"or_{self.id_or}"] = items
            return self.cond
        '''
        return items

    def and_cond(self, items):
        '''
        self.id_and = self.id_and + 1
        if self.cond:
            for key in items[1]:
                self.cond[f"and{self.id_and}"] = items[0] + '-' + key
                return self.cond
        else:
            self.cond[f"and_{self.id_and}"] = items
            return self.cond
        return self.cond
        '''

        return items

    def stmt(self, items):
        # print('1', items)
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
        with open(ir_file, 'r') as ir:
            self.vex = ir.read()
        self.grammar_path = Path(".").parent
        self.tokens = ['and', 'or']
        self.high = ['and']
        self.low = ['or']

    def __check_conditions(self, transformed_tree):
        matches = []
        conditions = []
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
        self.__search_conditions(conditions, d)

    def __priority(self, op1, op2):
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
            # print(el, end=" ")
            if el in self.tokens:
                if len(op_stack) == 0:
                    op_stack.append(el)
                    continue
                operator = op_stack[-1]
                if self.__priority(el, operator) == 1:
                    op_stack.append(el)
                elif self.__priority(el, operator) < 1:
                    postfix.append(op_stack.pop())
            else:
                postfix.append(el)
        while op_stack:
            postfix.append(op_stack.pop())
        return postfix

    def evaluate(self, postfix, d):
        stack = []
        for el in postfix:
            if el in self.tokens:
                val2 = stack.pop()
                val1 = stack.pop()
                string1 = d[val1]
                string2 = d[val2]
                if el == "and":
                    if string1 in self.vex and string2 in self.vex:
                        print("String ${} and string ${} are in the VEX".format(val1, val2))
                        stack.append(True)
                elif el == "or":
                    if string1 in self.vex or string2 in self.vex:
                        print("String ${} or string ${} are in the VEX".format(val1, val2))
                        stack.append(True)
            else:
                stack.append(el)
    def __search_conditions(self, conditions, d):
        # Verifico che la condizione sia presente tra le stringhe e se lo è verifico che la stringa esista nel codice
        # VEX
        condition = conditions[0]
        # print(conditions)
        if len(conditions) == 1:
            # print(condition)
            if condition in d:
                string = d[condition]
                if string in self.vex:
                    print("Found the string {}".format(string))
        else:
            infix = [y for x in conditions for y in (x if isinstance(x, list) else [x])]
            # print(infix)
            postfix = self.__postfix(infix)
            print(postfix, d)
            self.evaluate(postfix, d)

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
