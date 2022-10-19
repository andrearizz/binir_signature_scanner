# Progetto tesi

Prima versione del progetto di tesi

# Utilizzo

Per poter utilizzare il programma è necessario installare [angr](https://github.com/angr/angr) e [Lark](https://github.com/lark-parser/lark) con pip, oppure utilizzare il file requirements.txt:

`pip install -r requirementes.txt`

Il programma riceve in input un file binario ed un file di regole. Il file di regole utilizza una sintassi in stile Python:

```
def rule_1:
    matches:
        $x = "PUT(rsi) = 0x0000000000000002"
        $y = "PUT(rip) = 0x000000000040151d"
        $z = "LDbe:I64(t3)"
    condition:
        $y and ($x or $z)

def rule_2:
    matches:
        $x = "PUT(rip) = 0x000000000060111c"
    condition:
        $x
```    
        
Ora è possibile inserire più di una regola all'interno di un file di regole. Inoltre, lo statment "condition" riceverà sempre una sola riga: se la condizione è singola come nella regola chiamata `rule_2` verrà semplicemente verificato che nel binario liftato in VEX sia presente la stringa indicata.
Altrimenti è possibile valutare delle espressioni booleane che permettano di verificare secondo una certa logica quali match di stringhe ci sono nel VEX.

Lark è stato utilizzato per effettuare il parsing delle regole. Lark può essere utilizzato come libreria e si occupa di tutta la parte di generazione dell'albero di parsing (o abstract sytax tree) ma è necessario scrivere una grammatica. La grammatica (che andrà estesa) per questo semplice linguaggio è visualizzabile nel file `grammar.lark`.

# Esempio

L'esecuzione di questo comando:

`python3 main.py server rule1.txt -f main`


darà in output:

 ```
Condition $y = "PUT(rip) = 0x000000000040151d" is satisfied for the istruction at address: 0x40151b
Condition $x = "PUT(rsi) = 0x0000000000000002" is satisfied for the istruction at address: 0x401541
Condition $z = "LDbe:I64(t3)" is not satisfied
The condition $y and ( $x or $z ) from rule: rule_1 is satisfied
The condition $x = "PUT(rip) = 0x000000000060111c" for the rule rule_2 is not satisfied
```

È stato migliorato l'output in maniera da visualizzare quali stringhe matchino e quali no e l'indirizzo dell'istruzione assembly a cui appartengono. Ad esempio, analizzando staticamente il binario con un qualsiasi disassembler, notiamo che l'istruzione assembly all'indirizzo 0x40151b è `mov   esi, 2` che appunto, in VEX viene tradotto con la sola istruzione `PUT(rsi) = 0x0000000000000002`. Si ricorda che se il binario è compilato per essere "position indipendent" questo verrà interpretato in angr come se partisse dall'indirizzo 0x400000.

# Miglioramenti

Nei prossimi giorni verrà implementata la possibilità di utilizzare dei wildcard in maniera da poter rendere la ricerca meno restrittiva e più potente. Si conta di riuscire a raggiungere la possibilità di rendere meno restrittive le ricerche sui registri: se volessimo ricercare un qualsiasi registro che viene impostato a 2 e non ci importa esattamente di quale esso sia, potremmo ricercare una stringa del genere: `PUT(??) = 0x0000000000000002`. Tale sistema permette di verificare che un qualsiasi registro sia impostato a 0x2.
