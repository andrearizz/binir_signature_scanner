#include <stdio.h>

int main() {
    int i,N,j,k,cur;

    printf("Quanti numeri della successione vuoi visualizzare? ");
    scanf("%d", &N);

    j=0;
    k=1;

    printf("%d ",j);
    printf("%d ",k);

    for(i=2;i<N;i++) {
        cur=j+k;
        j=k;
        k=cur;
        printf("%d ",cur);
    }
}
