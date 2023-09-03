# SQL Injection vulnerabilities preventions in Java

## Table of contents
1. [What is SQL Injection?](#what-is-sql-injection)
2. [Preventing SQL Injection Vulnerabilities](#preventing-sql-injection-vulnerabilities)  
    - [Java Prepared Statement Example](#java-prepared-statement-example)
    - [Hibernate Query Language (HQL) Prepared Statement (Named Parameters) Example](#hibernate-query-language-hql-prepared-statement-named-parameters-example)
    - [Java Stored Procedure Example](#java-stored-procedure-example)

## What is SQL Injection?
SQL Injection flaws are introduced when software developers create dynamic database queries that include user supplied input.  

When SQLi attacks are successful, attackers can:  

- Log in to an app or a website front end without a password.  

- Access, extract, and delete stored data from secured databases.  

- Create their own database records or modify existing records, opening the door for further attacks.  

## Preventing SQL Injection Vulnerabilities:
To avoid SQL injection flaw is simple. Developers need to either: a) stop writing dynamic queries; and/or b) prevent user supplied input which contains malicious SQL from affecting the logic of the executed query.  

### Primary Defenses:

- Use of Prepared Statements (with Parameterized Queries). By using parameterized queries, data and commands in a query are separated at compile-time.  

- Use of Stored Procedures

- Allow-list Input Validation, Escaping All User Supplied Input

### Additional Defenses:

- Enforcing Least Privilege

**Code samples:**
### Java Prepared Statement Example:
```
String query = "SELECT account_balance FROM user_data WHERE user_name = "
             + request.getParameter("customerName");
try {
    Statement statement = connection.createStatement( ... );
    ResultSet results = statement.executeQuery( query );
}
...
```

```
// Perform input validation 
Pattern custNamePattern = Pattern.compile("[A-Za-z0-9_]+");
String custName = request.getParameter("customerName");
  if ( ! custNamePattern.matcher(custnName).matches())  {
         throw new YourValidationException( "Improper customer name format." );
   }

  try {
     
    // do what you want here, after its been validated ..
	String query = "SELECT account_balance FROM user_data WHERE user_name = ? ";
	PreparedStatement pstmt = connection.prepareStatement( query );
	pstmt.setString( 1, custName);
	ResultSet results = pstmt.executeQuery( );
  } catch(SQLException se) {       
	// … logging and error handling   
	}

```

**_Note:_** Constructing the parameterized query by concatenating user input (for example SELECT account_balance FROM user_data WHERE user_name = ? and address =" + address) still is a vulnerable code construction. 

### Hibernate Query Language (HQL) Prepared Statement (Named Parameters) Example:

```
//First is an unsafe HQL Statement
Query unsafeHQLQuery = session.createQuery("from Inventory where productID='"+userSuppliedParameter+"'");

//Here is a safe version of the same query using named parameters
Query safeHQLQuery = session.createQuery("from Inventory where productID=:productid");
safeHQLQuery.setParameter("productid", userSuppliedParameter);
```

### Java Stored Procedure Example:
```
// Perform input validation 
Pattern custNamePattern = Pattern.compile("[A-Za-z0-9_]+");
String custName = request.getParameter("customerName");
  if ( ! custNamePattern.matcher(custnName).matches())  {
         throw new YourValidationException( "Improper customer name format." );
   }

try {
  CallableStatement cs = connection.prepareCall("{call sp_getAccountBalance(?)}");
  cs.setString(1, custName);
  ResultSet results = cs.executeQuery();
  // … result set handling
} catch (SQLException se) {
  // … logging and error handling
}
```

