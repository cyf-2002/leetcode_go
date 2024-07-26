![image-20240722165634907](./assets/image-20240722165634907.png)

![image-20240722165602271](./assets/image-20240722165602271.png)





## 一. 用户服务

### 1. 密文保存

#### 1.1 MD5信息摘要算法

MD5生成的哈希值长度固定为128位；MD5已经被证明存在**碰撞攻击**；常用密码可以用**彩虹表暴力破解**

```go
func GenerateMD5Hash(input string) string {
    hasher := md5.New()
    // hasher := sha256.New() 
    hasher.Write([]byte(input))
    // 计算 MD5 哈希值并将其转换为十六进制字符串形式
    // Sum方法是追加一个值一并生成hash。传入nil得到str的hash值
    hash := hasher.Sum(nil)
    return hex.EncodeToString(hash)
}
```

- 加盐：将密码变为：随机字符串+用户密码

数据库保存密码时保存 **加密算法-盐值-加密后的密码**

用户登录时，

1. 用户输入【账号】和【密码】；
2. 系统通过用户名找到与之对应的【Hash值】和【Salt值】；
3. 系统将【Salt值】和【用户输入的密码】连接到一起；
4. 对连接后的值进行散列，得到【Hash值2】（注意是即时运算出来的值）；
5. 比较【Hash值1】和【Hash值2】是否相等，相等则表示密码正确，否则表示密码错误。



#### 1.2 Bcrypt算法

BCrypt算法**将salt随机并混入最终加密后的密码**，验证时也无需单独提供之前的salt，从而无需单独处理salt问题。

**`$2a$10$WzDl/B/Fo5g6upN4 dykWveqP5HrNw8fJ9KZZswEjh0L6LpZ8EzQ0K`**

`其中：$是分割符；2a是bcrypt加密版本号；10是cost的值；而后的前22位是salt值；再然后的字符串就是密码的密文`

生成密码和校验密码：

```java
// HashPassword hashes a plain text password using bcrypt.
func HashPassword(password string) (string, error) {
	// Generate hashed password with default cost.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// CheckPasswordHash compares a bcrypt hashed password with its possible plaintext equivalent.
func CheckPasswordHash(password, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
```

1. 虽然对同一个密码，每次生成的hash不一样，但是hash中包含了salt（hash产生过程：先随机生成salt，salt跟password进行hash）；
2. 在下次校验时，从hash中取出salt，salt跟password进行hash；得到的结果跟保存在DB中的hash进行比对。





































## 三. 库存微服务

### 1. 库存扣减

<img src="./assets/image-20240611012102295.png" alt="image-20240611012102295" style="zoom:67%;" />

