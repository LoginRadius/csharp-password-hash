# csharp-password-hash
.NET standard library to secure the passwords using multiple hashing algorithms.

## Features
* Secure the passwords using different types of hashing algos
* Uses of the different Encoding types
* Generating random salt
* Unit test cases to check the library fuctionality

## Getting Started
* Must have the latest version of the Visual Studio

Clone `csharp-password-hash` into your system using below commands:

Open command prompt and type below commands
```
git clone https://github.com/LoginRadius/csharp-password-hash
cd csharp-password-hash
csharp-password-hash.sln
```
It will open the solution into the Visual Studio
## Usage
Below are samples to show how you might use the library.

### Create user model class
```C#
public class User{
  public string EmailId{get;set;}
  public string Password{get;set;}
}
```
### Create user object
```C#
//Create user object and set emailId and password properties
var userObject = new User
{
  EmailId = "test@gmail.com",
  Password = "Test#11"
};
```
### Example 1 - Create HashConfig object (When GeneratePerPasswordSalt is true)
```C#
//Create HashConfig object and set below properties
var hashConfig = new HashingConfig
{
  GeneratePerPasswordSalt = true, // This property is used when we have generate different password salt
  GlobalSalt = null, // This is used when we have to use the same salt for every password
  SaltedPasswordFormat = "#PasswordPlaceHolder#--#SaltPlaceHolder#",// Format which will be used in salted password 
  HashingAlgo = HashingAlgo.MD5, // Hashing algo which we want to use
  PasswordHashEncodingType = EncodingType.Default // Encoding type for password hashing
};
```
### Check password (When GeneratePerPasswordSalt is true)
```C#
//Combine the user object and HashConfig object (When GeneratePerPasswordSalt is true)
//Create method to check password
public void ValidatePassword()
{
  var userObject = new User
  {
   EmailId = "test@gmail.com",
   Password = "Test#11"
  };
  var hashConfig = new HashingConfig
  {
    GeneratePerPasswordSalt = true,
    GlobalSalt = null,
    SaltedPasswordFormat = "#PasswordPlaceHolder#--#SaltPlaceHolder#",
    HashingAlgo = HashingAlgo.MD5,
    PasswordHashEncodingType = EncodingType.Default
  };
  var passwordHashing = new PasswordHashing(); // Create password hashing object
  var hash = passwordHashing.GetHash(userObject.Password, hashConfig); // GetHash for the password
  var match = passwordHashing.CheckPassword(hash, hashConfig, userObject.Password); //Check password
}
```

### Example 2 - Create HashConfig object (When GeneratePerPasswordSalt is false)
```C#
//In that case we have to set the GlobalSalt property
//Create HashConfig object and set below properties
var hashConfig = new HashingConfig
{
  GeneratePerPasswordSalt = false, \
  GlobalSalt = SecureSalt, 
  SaltedPasswordFormat = "#PasswordPlaceHolder#--#SaltPlaceHolder#",
  HashingAlgo = HashingAlgo.MD5, 
  PasswordHashEncodingType = EncodingType.Default 
};
```
### Check password (When GeneratePerPasswordSalt is false)
```C#
//Combine the user object and HashConfig object (When GeneratePerPasswordSalt is false)
//Create method to check password
public void ValidatePassword()
{
  var userObject = new User
  {
   EmailId = "test@gmail.com",
   Password = "Test#11"
  };
  var hashConfig = new HashingConfig
  {
    GeneratePerPasswordSalt = false,
    GlobalSalt = "SecureSalt",
    SaltedPasswordFormat = "#PasswordPlaceHolder#--#SaltPlaceHolder#",
    HashingAlgo = HashingAlgo.MD5,
    PasswordHashEncodingType = EncodingType.Default
  };
  var passwordHashing = new PasswordHashing(); // Create password hashing object
  var hash = passwordHashing.GetHash(userObject.Password, hashConfig); // GetHash for the password
  var match = passwordHashing.CheckPassword(hash, hashConfig, userObject.Password); //Check password
}
```

## Contributing
Would love any contributions by you, including better documentation, tests or more robust functionality. Please follow the [contributing guide](CONTRIBUTING.md)

## License
[MIT](LICENSE)
