**<sc, nc, mi, si, bt, os, cb>**，对应含义如下：

1. **sc (String Constants)**：代码块中的字符串常量数量。
2. **nc (Numeric Constants)**：代码块中的数值常量数量。
3. **mi (Memory Instructions)**：内存操作指令数（如`mov`, `call`, `lea`等涉及内存访问的指令）。
4. **si (Sum Instructions)**：算术 / 逻辑运算指令数（如`add`, `sub`, `inc`, `adc`等）。
5. **bt (Betweenness)**：介数中心性，衡量代码块在控制流图中的结构重要性（通过图论算法计算）。
6. **os (Offspring)**：子节点数，即代码块的直接后继基本块数量。
7. **cb (Outgoing Edges)**：出边数，即代码块在控制流图中的出边数量（与`os`通常一致）。