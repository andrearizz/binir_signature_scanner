# Progetto tesi

Prima versione del progetto di tesi

# Utilizzo

Per poter utilizzare il programma è necessario installare [angr](https://github.com/angr/angr) e [Lark](https://github.com/lark-parser/lark) con pip, oppure utilizzare il file requirements.txt:

`pip install -r requirementes.txt`

Il programma riceve in input un file binario ed un file di regole. Il file di regole utilizza una sintassi in stile Python:

```
def rule_1:
    matches:
        $x = "PUT(rdx) = 0x0000000000000000"
        $y = "PUT(rax) = 0x0000000000000002"
        $z = "PUT(rip) = 0x000000000060111c"
    condition:
        $z
```    
        
In questa prima versione è solamente possibile inserire su ogni riga la stringa da matchare tramite assegnamento ad una variabile. Analogamente ogni stringa devrebbe essere nella forma `$variabile = "stringa"`.

Lark è stato utilizzato per effettuare il parsing delle regole. Lark può essere utilizzato come libreria e si occupa di tutta la parte di generazione dell'albero di parsing (o abstract sytax tree) ma è necessario scrivere una grammatica. La grammatica (che andrà estesa) per questo semplice linguaggio è visualizzabile nel file `grammar.lark`.

# Esempio

L'esecuzione di questo comando:

`python3 main.py server rule1.txt`

darà in output:

`Found the string PUT(rip) = 0x000000000060111c`

