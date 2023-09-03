# Open Redirect vulnerabilities preventions in Java/JavaScript

## Table of contents
1. [What are Open Redirects?](#what-are-open-redirects)
2. [Scenarios for Exploiting Open Redirect Vulnerabilities](#scenarios-for-exploiting-open-redirect-vulnerabilities)
3. [Preventing Open Redirection Vulnerabilities](#preventing-open-redirection-vulnerabilities)

## What are Open Redirects?  
Redirects are a common part of website operations but can cause application security risks when carelessly implemented. An open redirect endpoint accepts untrusted inputs as the target URL, allowing attackers to redirect users to a malicious website and opening up a wide array of attack vectors. Exploitation can be as simple as manually changing a URL parameter value to an attacker-controlled site.

There are three types of redirects and all of them can, in specific scenarios, be used to exploit open redirection:

- Header-based redirects use the [HTTP Location header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Location) to specify a new browser location. This is the most common redirection method.  
Example: `Location: https://www.attacker.com/`

- [Meta tag redirects](https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections#html_redirections) use the HTML meta tag to navigate to a new location.  
Example: `<meta http-equiv = "refresh" content = "0;url=https://www.attacker.com/" />`

- DOM-based redirects use JavaScript to manipulate DOM window properties.  
Example: `window.location = 'https://www.attacker.com'`

## Scenarios for Exploiting Open Redirect Vulnerabilities:
- Phishing Attacks  
- Token Theft Scenario  
- Server-Side Request Forgery (SSRF)  
- Cross-Site Scripting (XSS) Through Redirection to Another Protocol  

## Preventing Open Redirection Vulnerabilities:
- Simply avoid using redirects and forwards.
- If used, do not allow the URL as user input for the destination.
- Disallow Offsite Redirects

    You can prevent redirects to other domains by checking the URL being passed to the redirect function.  
    Make sure all redirect URLs are **relative paths** – i.e. they start with a single / character.   
    (Note that URLs starting with // will be interpreted by the browser as a protocol agnostic, absolute URL – so they should be rejected too.)

 - If you do need to perform external redirects, consider whitelisting the individual sites that you permit redirects to.

 **Code samples:**
 ```
 protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  String destination = req.getParameter("url");
  resp.sendRedirect(destination); // Noncompliant
}
 ```

Following code's behavior is changed to only allow targets from a group of destinations that are defined in advance on the server side. 
Instead of permitting access to any URL that a user provides, the new function uses a list of all permissible target URLs (a whitelist), then assigns an "indirect" value to each target. 
These indirect values will now appear in the URL instead of the literal destination. 
A valid link, such as `http://www.trustworthy.org/#/redirect?url=2`, sends the user to the URL represented by the index 2. 
If the attacker tries to exploit, the URL `http://www.trustworthy.org/#/redirect?url=stealyourmoney.org` will not perform the redirect. 
Doing it this way prevents the attacker from tricking someone into visiting any URL that they type.

```
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
  
		Integer targetIndex = Integer.parseInt(request.getParameter("url"));

		String[] safeURLs = { "https://allowed_url1.com", "https://allowed_url2.com", "https://allowed_url3.com" };
		HashMap<Integer, String> urlMap = new HashMap<Integer, String>();
		for (int i = 0; i < safeURLs.length; i++) {
			urlMap.put(i+1, safeURLs[i]);
		}
		if(urlMap.containsKey(targetIndex)) {
			response.sendRedirect(urlMap.get(targetIndex));
		}
}
```

In some situations this approach is impractical because the set of legitimate URLs is too large or too hard to keep track of. 
In such cases, validate the redirect url  and restrict the domains that users can be redirected to, 
which can at least prevent attackers from sending users to malicious external sites.

```
import org.apache.commons.validator.routines.UrlValidator;

protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {      
 		String target = request.getParameter( "url" );
		String actualDomain = request.getServerName();

		String[] validDomainValues = new String[]{ "www-sit-intra.nl.eu.abnamro.com","www-st2-intra.nl.eu.abnamro.com",
				"www-st3-intra.nl.eu.abnamro.com","accessonline-et-intra.nl.eu.abnamro.com","accessonline-intra.nl.eu.abnamro.com"};

		if (target != null && !target.trim().isEmpty() &&
				validateUrl(target) &&
				validateDomain(validDomainValues, actualDomain)) {

			response.sendRedirect(target);
		}
}


private static boolean validateUrl(String url) {
		String[] schemes = {"http","https"}; // DEFAULT schemes = "http", "https", "ftp"
		UrlValidator urlValidator = new UrlValidator(schemes);
		return urlValidator.isValid(url);
}

private static boolean validateDomain(String[] validDomainValues, String targetDomain) {
		boolean isValid = false;
		for(String domainName: validDomainValues){
			if(domainName.equalsIgnoreCase(targetDomain)){
				isValid = true;
				break;
			}
		}
		return isValid;
}
```

**Disallowing Offsite Redirects:**
Relative links inside your site will always start with a single / character.  
You can prevent redirects to other domains by checking the URL being passed to the redirect function.  
```
protected void doGet(HttpServletRequest request, HttpServletResponse response) {
  String url = request.getParameter("url");
  if (url != null && isRelative(url)) {
    response.sendRedirect(url);
  }
}

// Allow anything starting with "/", except paths starting
// "//" and "/\".
private boolean isRelative(String url) {
  return url.matches("/[^/\\]?.*");
}
```

**References:**
[Unvalidated Redirects and Forwards - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)