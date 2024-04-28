#include <stdio.h>

int main(){
    char buf[10];
    puts("ROP is amazing");
    read(0,buf,0x50);
}