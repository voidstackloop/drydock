void trigger_leak(){
    int *leaked=new int(1337);
}

void trigger_double_free(){
    int *leaked=new int(42);
    delete leaked;
    delete leaked;
}

void trigger_invalid_free(){
    int stack_var=100;
    delete &stack_var;
}

int main(){
    trigger_leak();
    trigger_double_free();
    trigger_invalid_free();
    return 0;
}
