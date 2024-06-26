# BinIR Signature Scanner

Versione più aggiornata del progetto di tesi

# Utilizzo

Per poter utilizzare il programma è necessario installare [angr](https://github.com/angr/angr) e [Lark](https://github.com/lark-parser/lark) con pip, oppure utilizzare il file requirements.txt:

`pip install -r requirementes.txt`

Il programma riceve in input un file binario ed un file di regole. Il file di regole utilizza una sintassi in stile Python:

```
def rule_1:
    matches:
        $x = "PUT(rax) = 0x40130d"
        $y = "PUT(??) = 0x40151d"
        $z = "LDle:I??(t3)"
    condition:
        $y and ($x1 or $z)

def rule_2:
    matches:
        $x = "PUT(??) = 0x000000000060111c"
    condition:
        $x
```    
        
Ora è possibile inserire più di una regola all'interno di un file di regole. Inoltre, lo statment "condition" riceverà sempre una sola riga: se la condizione è singola come nella regola chiamata `rule_2` verrà semplicemente verificato che nel binario liftato in VEX sia presente la stringa indicata.
Altrimenti è possibile valutare delle espressioni booleane che permettano di verificare secondo una certa logica quali match di stringhe ci sono nel VEX.

Lark è stato utilizzato per effettuare il parsing delle regole. Lark può essere utilizzato come libreria e si occupa di tutta la parte di generazione dell'albero di parsing (o abstract sytax tree) ma è necessario scrivere una grammatica. La grammatica per questo semplice linguaggio è visualizzabile nel file `grammar.lark`.

È possibile utilizzare il wildcard ("??") per rendere la ricerca di pattern meno stringente. Ad esempio nella regola `rule_1` la stringa rappresentata da `$y` è `"PUT(??) = 0x40151d"`, pertanto qualsiasi istruzione nel VEX che imposterà un registro al valore 0x40151d verrà riconosciuta. Si noti come il wildcard alla stringa `$z` non è stata applicata al registro ma al nome dell'istruzione stessa. Infatti, in VEX l'istruzione di caricamento di un valore in memoria può essere LDle:I64 o LDle:I32. Per rendere la ricerca più flessibile si potrebbe pensare di ricercare pattern in maniera indipendente dall'architettura utilizzando i wildcard in questo modo `LDle:I??(t3)`. Si noti ancora che `le` nel nome di questa istruzione sta ad indicare `little endian`, analogamente `be` indica `big endian`. Ancora una volta si potrebbe considerare un pattern del genere `LD??:I??(t3)`.
È possibile specificare valori esadecimali non più legati  alla rappresentazione in VEX. Infatti, qualsiasi valore esadecimale per un binario a 64 bit in VEX è rappresentato da 16 caratteri (vedi regola 2). Ora è possibile specificare i valori in maniera più comoda come nella regola 1.


È possibile specificare il nome di una funzione all'interno della quale eseguire la ricerca di pattern con il flag `-f function_name`. Oppure specificare i `flag -s start_address` e `-e end_address` per specificare un range in cui effettuare la ricerca. Alternativamente si può specificare solo il flag di start per eseguire la ricerca di patter dall'indirizzo specificato fino alla fine del binario.

# Esempio

L'esecuzione di questo comando:

`python3 main.py server rule1.txt -f main`


darà in output:

 ```
Condition $y = "PUT(rip) = 0x40151d" is satisfied for the istruction at address: 0x40151b
Condition $x = "PUT(rax) = 0x40130d" is not satisfied
Condition $z = "LDle:I??(t3)" is satisfied for the istruction at address: 0x401457 with instruction "t6 = LDle:I32(t3)"
The condition $y and ( $x or $z ) from rule: rule_1 is satisfied
Condition $x = "PUT(??) = 0x60111c" is not satisfied
The condition $x from rule: rule_2 is not satisfied
```

È stato migliorato l'output in maniera da visualizzare quali stringhe matchino e quali no e l'indirizzo dell'istruzione assembly a cui appartengono. Ad esempio, analizzando staticamente il binario con un qualsiasi disassembler, notiamo che l'istruzione assembly all'indirizzo 0x40151b è `mov   esi, 2` che appunto, in VEX viene tradotto con la sola istruzione `PUT(rsi) = 0x0000000000000002`. Si ricorda che se il binario è compilato per essere "position indipendent" questo verrà interpretato in angr come se partisse dall'indirizzo 0x400000.

# Possibli miglioramenti

È possibile permettere di specificare condizioni del tipo `all of them` o `any of them` per indicare la ricerca rispettivamente di tutte le stringhe o di almeno una stringa tra quelle specificata. Inoltre, si potrebbe estendere questo tipo di condizioni permettendo espressioni del tipo `all of ($x1 $x2)` in cui si vuole che sia $x1 che $x2 siano soddisfatte tale scrittura equivale a `$x1 and $x2`. Analogamente si potrebbero rappresentare espressioni del tipo `any of ($x $y)` oppure `2 of ($x $y $z)` etc. Tutte queste espressioni dovrebbero comunque essere integrate anche con la valutazione delle espressioni booleane per permettere condizioni del tipo:
`$y and all of ($x $z)` e così via.
 
A differenza di YARA, non è possibile fare ricerce del tipo `all of ($x*)` per richiedere che tutte le stringhe di tipo `$x` siano verificate. È necessario inserire tutte le stringhe che si vuole vengano verificate. Se esistono due stringhe di tipo `$x` come `$x1` e `$x2` bisognerà scrivere una condizione come la seguente: `all of ($x1 $x2)`.

È anche possibile specificare il numero di condizioni che devono essere verificate con espressioni del tipo `2 of them`, `3 of ($x $y $z $w)` e così via.

Segue un esempio che mostra l'utilizzo di regole del genere.

Data la regola:
```
def rule_1:
    matches:
        $x1 = "PUT(rax) = 0x40130d"
        $x2 = "PUT(rip) = 0x40151d"
        $z = "LDle:I??(t3)"
    condition:
        all of ($x1 $x2) or $z
```

l'output sarà:
```
Condition $x1 = "PUT(rax) = 0x40130d" is not satisfied
Condition $z = "LDle:I??(t3)" is satisfied for the istruction at address: 0x401457 with instruction "t6 = LDle:I32(t3)"
The condition "all of ( $x1 $x2 ) or $z" from rule: "rule_1" is satisfied
```
Ed effettivamente è corretto in quanto la stringa `$x1` non è presente e questo basta ad invalidare la condizione `all of`, senza necessità di verificare anche la stringa `$x2` ma essendo presente la `$z` la condizione è verificata in quanto le due parti sono unite dalla condizione `or`.

# Ricerca in sequenza

È stata implementa la possibilità di ricercare pattern di codici in sequenza. Segue un'esempio di regola che identifica per architture x86_64, x86, aarch32 e aarch64, la chiamata alla system call `execve`.

```
def execve_syscall:
    matches:
        $x1 = "STle(??) = 0x00000000"
        $x2 = "STle(??) = 0x00000000"
        $x3 = "STle(??) = ??"
        $y1 = "PUT(??) = 0x0"
        $y2 = "PUT(??) = 0x0"
        $y3 = "PUT(??) = ??"
        $w = "PUT(r0) = ??"
        $z = "Ijk_Call"
    condition:
       {$y1 1 $y2 1 $y3 1 $z} or {$x1 1 $x2 2 $x3 1 $z} or {$y1 1 $y2 2 $y3 1 $z} or {$y1 1 $y2 3 $w 1 $z}
```
Attualmente la regola è stata testa solamente con i file eseguibili, il quale codice sorgente è nel file `reverse_shell.c`, presenti tra i file disponibili.

# Ricerca di valori nei dati RAW

Per poter analizzare in maniera migliore un binario, una sola analisi statica sul codice è spesso troppo limitante. 
Avendo comunque a disposizione il file binario si è deciso di estrarre dati "utili" come i valori di determinate stringhe, direttamente dai dati raw.
In questa maniera è possibile analizzare anche da un punto di vista più semantico il binario, combinando aspetti semantici e aspetti sintattici.

Sono state scritte due signature (cartella `rules`) che cercano di catturare il comportamento di una reverse shell.
Se si sa che un programma (in questo caso malevolo) si connette sempre attraverso la stessa porta (9001 in questo caso)
sempre allo stesso indirizzo ip (127.0.0.1 in questo caso), la signature cerca di catturare l'utilizzo di tale porta (nel codice VEX) e 
di considerare eventuali valori nel raw come indirizzo ip e chiamate a funzione della libc come execve, socket etc.

La seconda signature, `rule2.txt`, considera un caso semplice di programma malevolo "offuscato". Infatti, se nell'esempio precedente 
si sapeva a priori il valore della porta e dell'indirizzo ip, qui si considera un caso in cui tali valori sono cifrati.
Banalmente, il codice (sorgente nella cartella `sources`) utilizza dei valori (come l'indirizzo ip) precedentemente cifrati tramite xor e
ha a disposizione la chiave di cifratura e decifratura. Dunque, prima di utilizzarli decifra tali valori. La signature cerca di catturare il comportamento
dell'operazione di XOR analizzando il comportamento di tale funzione dal punto di vista del codice in IR, unita ad aspetti semantici come chiamate 
alle funzioni precedentemente discusse per il primo esempio.
