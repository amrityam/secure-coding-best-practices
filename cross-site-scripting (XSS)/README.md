# Cross Site Scripting(XSS) vulnerabilities preventions in Java and JavaScript

In Cross-site Scripting (XSS) attack, the attacker aims to execute malicious scripts in a web browser of the victim by including malicious code in a legitimate web page or web application.
The attacker can carry out any actions that the user is able to perform and to access any of the user's data. If the victim user has privileged access within the application, then the attacker might be able to gain full control over all of the application's functionality and data.

The root cause of XSS vulnerabilities is when a web application uses untrusted input without performing proper validation or encoding and directly process render user inputs on web pages.

## Types of XSS attacks:
**Reflected XSS -**  where the malicious script comes from the current HTTP request.  

**Stored XSS -** where the malicious script comes from the website's database.  

**DOM-based XSS -** where the vulnerability exists in client-side code rather than server-side code.

## Defending against XSS attack:
1. Output Encode all user supplied input e.g. OWASP Java Encoder

2. Perform Allow List Input Validation for all user inputs in server side

3. Enable security headers: X-XSS-Protection and Content-Security-Policy response headers

4. Set HttpOnly Cookie

### (1) Output encode all user supplied inputs:
Fixed code examples using Encoder from [OWASP Java Encoder Project](https://wiki.owasp.org/index.php/OWASP_Java_Encoder_Project)

```
<%import org.owasp.encoder.Encode;%>

Search results for <b><%=Encode.forHtml(searchCriteria)%></b>:
<!-- ... -->
```

```
import org.owasp.encoder.Encode;  

if(request.getParameter("swiftAddress") != null ){
	swiftAddress = Encode.forHtml(request.getParameter("swiftAddress"));
}	
```

Same result can be achieved using [HtmlUtils](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/web/util/HtmlUtils.html) from Spring framework:

```
<%import org.springframework.web.util.HtmlUtils;%>

Search results for <b><%=HtmlUtils.htmlEscape(searchCriteria)%></b>:
<!-- ... -->
```

```
import org.springframework.web.util.HtmlUtils;

if(request.getParameter("swiftAddress") != null ){
	swiftAddress = HtmlUtils.htmlEscape(request.getParameter("swiftAddress"));
}	
```

### More information on different encoding contexts:
The encoding pattern using OWASP Java Encoder is **"Encode.forContextName(untrustedData)"**, where "ContextName" is the name of the target context and "untrustedData" is untrusted output.

**Basic HTML Context:**
```
<body><%= Encode.forHtml(UNTRUSTED) %></body>
```

**HTML Content Context:**
```
<textarea name="text"><%= Encode.forHtmlContent(UNTRUSTED) %></textarea>
```

**HTML Attribute Context:**
```
<input type="text" name="address" value="<%= Encode.forHtmlAttribute(UNTRUSTED) %>" />
```

Generally **Encode.forHtml(UNTRUSTED)** is also safe but slightly less efficient for the above two contexts (for text area content and input value text) since it encodes more characters than necessary but might be easier for developers to use.

**CSS Context:**
```
<div style="width:<= Encode.forCssString(UNTRUSTED) %>">
<div style="background:<= Encode.forCssUrl(UNTRUSTED) %>">
```

**JavaScript Block Context:**
```
<script type="text/javascript">
 var msg = "<%= Encode.forJavaScriptBlock(UNTRUSTED) %>";
 alert(msg);
</script>
```

**JavaScript Variable Context:**
```
<button 
 onclick="alert('<%= Encode.forJavaScriptAttribute(UNTRUSTED) %>');">
 click me</button>
```

JavaScript Content Notes: **Encode.forJavaScript(UNTRUSTED)** is safe for the above two contexts, but encodes more characters and is less efficient.

**Encode URL parameter values:**
```
<a href="/search?value=<%= Encode.forUriComponent(UNTRUSTED) %>&order=1#top">
```

**Encode REST URL parameters:**
```
<a href="/page/<%= Encode.forUriComponent(UNTRUSTED) %>">
```

**Handling a Full Untrusted URL:**  
When handling a full URL with the OWASP Java encoder, first verify the URL is a legal URL.
```
String url = validateURL(untrustedInput);
```

Then encode the URL as an HTML attribute when outputting to the page. Note the linkable text needs to be encoded in a different context.

```
<a href="<%= Encode.forHtmlAttribute(untrustedUrl) %>">
 <%= Encode.forHtmlContent(untrustedLinkName) %>
</a>
```

**Reference:**  
[OWASP Java Encoder Project](https://wiki.owasp.org/index.php/OWASP_Java_Encoder_Project#tab=Main)
   
### Fixing DOM based XSS vulnerabilities
DOM-based XSS vulnerabilities usually arise when JavaScript takes data from an attacker-controllable source, such as the URL, and passes it to a sink that supports dynamic code execution, such as eval() or innerHTML. This enables attackers to execute malicious JavaScript, which typically allows them to hijack other users' accounts.

To deliver a DOM-based XSS attack, attacker needs to place data into a source so that it is propagated to a sink and causes execution of arbitrary JavaScript.

The following sinks can lead to DOM-XSS vulnerabilities.

**JavaScript Sinks:**
```
document.write()
document.writeln()
document.domain
element.innerHTML
element.outerHTML
element.insertAdjacentHTML
element.onevent
```

**jQuery Sinks:**
```
add()
after()
append()
animate()
insertAfter()
insertBefore()
before()
html()
prepend()
replaceAll()
replaceWith()
wrap()
wrapInner()
wrapAll()
has()
constructor()
init()
index()
jQuery.parseHTML()
$.parseHTML()
```

To prevent DOM-based cross-site scripting, sanitize all untrusted data, even if it is only used in client-side scripts. If you have to use user input on your page, always use it in the text context, never as HTML tags or any other potential code. Use only safe functions like document.innerText and document.textContent.

[DOMPurify](https://github.com/cure53/DOMPurify) library can be used to sanitizes HTML in order to prevents XSS attacks.

**Examples:**
```
<script>
  var source = "Hello " + decodeURIComponent(location.hash.split("#")[1]);  //Source
  var divElement = document.createElement("div");
  divElement.innerHTML = source;  //Sink
  document.body.appendChild(divElement);
</script>
```

```
<script>
  var source = "Hello " + decodeURIComponent(location.hash.split("#")[1]);  //Source
  var divElement = document.createElement("div");
  divElement.innerHTML = DOMPurify.sanitize(source);  //Sink
  document.body.appendChild(divElement);
</script>
```

### (2) Perform allow list input validation on server side for all user inputs:
As a defense-in-depth strategy, server side input validation is essential for securing an application. [Bean Validation](https://beanvalidation.org/) or commonly known as [JSR-380](https://beanvalidation.org/2.0-jsr380/) is a Java standard that is used to perform validation in Java applications.

Bean Validation works by defining constraints to the fields of a class by annotating them with certain annotations.

**Common Validation Annotations:**  
- `@NotNull:` to say that a field must not be null.

- `@NotEmpty:` to say that a list field must not empty.

- `@NotBlank:` to say that a string field must not be the empty string (i.e. it must have at least one character).

- `@Min and @Max:` to say that a numerical field is only valid when it’s value is above or below a certain value.

- `@Pattern:` to say that a string field is only valid when it matches a certain regular expression.

- `@Email:` to say that a string field must be a valid email address

There are two things we can validate for any incoming HTTP request in a Spring REST controller:

- the request body,

- variables within the path (e.g. id in /foos/{id}) and request parameters.

### Validating The Request Body:
In POST and PUT requests, it’s common to pass a JSON payload within the request body. Spring automatically maps the incoming JSON to a Java object. Now, we want to check if the incoming Java object meets our requirements.

This is our incoming payload class:
```
class Input {

  @Min(1)
  @Max(10)
  private int numberBetweenOneAndTen;

  @NotNull   
  @Pattern(regexp = "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$")
  private String ipAddress;
  
  // ...
}
```

To validate the request body of an incoming HTTP request, we annotate the request body with the `@Valid` annotation in a REST controller:

```
@RestController
class ValidateRequestBodyController {

  @PostMapping("/validateBody")
  ResponseEntity<String> validateBody(@Valid @RequestBody Input input) {
    return ResponseEntity.ok("valid");
  }

}
```

### Validating Path Variables and Request Parameters:
```
@RestController
@Validated
class ValidateParametersController {

  @GetMapping("/validatePathVariable/{id}")
  ResponseEntity<String> validatePathVariable(
      @PathVariable("id") @Min(5) int id) {
    return ResponseEntity.ok("valid");
  }
  
  @GetMapping("/validateRequestParameter")
  ResponseEntity<String> validateRequestParameter(
      @RequestParam("param") @Min(5) int param) { 
    return ResponseEntity.ok("valid");
  }
}
```
If the `@Validated` is failed, it will trigger a `ConstraintViolationException`. To return user-friendly messages to the client, you should use an [exception handler](https://springframework.guru/exception-handling-in-spring-boot-rest-api/) to process validation errors.

**Java Regex Usage Example:**

Example validating the parameter "zip" using a regular expression.

```
private static final Pattern zipPattern = Pattern.compile("^\d{5}(-\d{4})?$");

public void doPost( HttpServletRequest request, HttpServletResponse response) {
  try {
      String zipCode = request.getParameter( "zip" );
      if ( !zipPattern.matcher( zipCode ).matches() ) {
          throw new YourValidationException( "Improper zipcode format." );
      }
      // do what you want here, after its been validated ..
  } catch(YourValidationException e ) {
      response.sendError( response.SC_BAD_REQUEST, e.getMessage() );
  }
}
```

**References:**  
[Bean Validation - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Bean_Validation_Cheat_Sheet.html)

[The Bean Validation reference implementation. - Hibernate Validator](https://hibernate.org/validator/)

[Validation in Spring Boot | Baeldung](https://www.baeldung.com/spring-boot-bean-validation)

[Overview (Apache Commons Validator 1.7 API)](https://commons.apache.org/proper/commons-validator/apidocs/overview-summary.html)

### (3) Enable security headers:
X-XSS header is used to defend against Cross-Site Scripting attacks. Using this feature, the browser does not render when it detects an XSS attempt. However, some web browsers haven't implemented the XSS auditor. In this case, they don't make use of the X-XSS-Protection header.

To overcome this issue, we can also use the Content Security Policy (CSP) feature. The Content-Security-Policy header is an improved version of the X-XSS-Protection header and provides an additional layer of security.

**Example:**

To enable these headers using Spring Security, we need to configure the Spring application to return a *XSS protection* and *Content-Security-Policy* header by providing a *WebSecurityConfigurerAdapter* bean:

```
@Configuration
public class SecurityConf extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
          .headers()
          .xssProtection()
          .and()
          .contentSecurityPolicy("script-src 'self'");
    }
}
```

**References:**

[Prevent Cross-Site Scripting (XSS) in a Spring Application | Baeldung](https://www.baeldung.com/spring-prevent-xss)

[X-XSS-Protection - HTTP | MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)

[Content Security Policy (CSP) - HTTP | MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)


### (4) Set HttpOnly Cookie:
HttpOnly cookies are used to prevent cross-site scripting (XSS) attacks and are not accessible via JavaScript's Document.cookie API.

When the HttpOnly flag is set for a cookie, it tells the browser that this particular cookie should only be accessed by the server.

- **_httpOnly:_** if true then browser script won't be able to access the cookie

- **_secure:_** if true then the cookie will be sent only over HTTPS connection

Those flags can be set  for session cookie in the *web.xml:*
```
<session-config>
    <session-timeout>1</session-timeout>
    <cookie-config>
        <http-only>true</http-only>
        <secure>true</secure>
    </cookie-config>
</session-config>
```

If you are using Spring Boot, these flags can be set in *application.properties* file.
```
server.servlet.session.cookie.http-only=true
server.servlet.session.cookie.secure=true
```

**Reference:**  
[Control the Session with Spring Security | Baeldung ](https://www.baeldung.com/spring-security-session)