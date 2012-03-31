Request
=======
The 'Request' class is a wrapper for HTTP requests. It provides a collection of simple methods for easily and reliably retrieving information associated with a HTTP request.

Usage
-----
### General Data Access Methods
The following methods can be used to retrieve data from any of the PHP superglobal arrays associated with a HTTP request: ``get``, ``post``, ``files``, ``session``, ``cookie``, ``env``, and ``server``.

For example, to get the 'username' property submitted via a POST request:

    $username = Request::post('username');

The arguments passed to the data access methods are case sensitive. Also, header variables, which are accessible via the ``server`` method, must be specified in uppercase with underscores rather than hyphens and a with a HTTP_ prefix.

    // Request the Cache-Control header:
    $cc = Request::server('HTTP_CACHE_CONTROL');

The access methods will return NULL if the requested variable is undefined, unless you provide a default value:

    // Will return Fred Nurk if $_POST['username'] is undefined.
    $username = Request::post('username', 'Fred Nurk');

If called without a parameter, the methods will return an array containing all variables from the associated superglobal:

    // Requested: http://a.com/?username=fred&id=1
    // Returned:  array('username' => 'fred', 'id' => '1')
    $input = Request::get();

To simulate HTTP methods not supported by browsers (e.g. PUT, DELETE), assign the method name to a request variable named HTTP_X_HTTP_METHOD_OVERRIDE. For example:

    // To simulate the PUT method via a HTML form:
    <form method="post">
      <input type="text" name="username" />
      <input type="submit" name="Submit" />
      <input type="hidden" name="HTTP_X_HTTP_METHOD_OVERRIDE" value="PUT" />
    </form>

To access input data submitted via PUT or DELETE, use the ``put`` and ``delete`` methods. They work just like ``get`` and ``post``.

Use the ``body`` method to get the raw body of a request. An optional default value can be provided.

    // Requested: The form above is submitted with username 'Fred'
    // Returned:  username=Fred&Submit=Submit&HTTP_X_HTTP_METHOD_OVERRIDE=PUT
    $body = Request::body();

The ``input`` method also works like the other access methods, and can be used to retrieve input data irrespective of whether it was submitted via a GET, POST, PUT or DELETE request. If called without a parameter, ``input`` will return an array containing the data from all input superglobals. The ``all`` method takes it one step further, and will also return data contained within the $_FILES array.

Use the ``only`` method to only return a subset of items from the input data:

    // Only get the email variable from the input data:
    $email = Request::only('email');

    // Only get the username and email variables from the input data:
    $input = Request::only(array('username', 'email'));

Conversely, use the ``except`` method to return all input data except for an item or array of items:

    // Get all input data except for username and email:
    $input = Request::except(array('username', 'email'));

The ``only`` and ``except`` methods can be called with either a string or an array, but both will always return an array or NULL.

Use the ``has`` method to check if one or more variables exist within the input data. The method will return FALSE if at least one variable is undefined or empty; otherwise it will return TRUE.

    // Has `id` been submitted?
    if (Request::has('id')) { echo 'The `id` exists.'; }

    // Have `id` and `name` both been submitted?
    if (Request::has(array('id', 'name'))) { // do cool stuff }

### Request Properties
The ``host`` method returns the domain name, or host name, of the request. A default value can be returned if the host name cannot be determined.

    // Requested: http://a.com/blog/
    // Returned:  a.com
    $host = Request::host();

The ``port`` method returns the target port number of the request. If called with a parameter value of TRUE (indicating the result should be "decorated"), the method will prefix the port number with a colon, but will not return a value for standard ports 80 and 443.

    // Requested: http://a.com/blog/
    // Returned:  80
    $port = Request::port();

    // No value returned for standard ports:
    $port = Request::port(TRUE);

The ``protocol`` method returns the version of the HTTP protocol used in the request. The method accepts a default value, but if none is provided, and the protocol cannot be determined, 'HTTP/1.1' will be returned.

The ``scheme`` method returns the HTTP scheme used in the request (i.e. http or https):

    // Requested: http://a.com/
    // Returned:  http
    $scheme = Request::scheme();

    // Requested: http://a.com/
    // Returned:  http://
    $scheme = Request::scheme(TRUE);

The ``secure`` method returns TRUE if the HTTP scheme is 'https' and FALSE if the scheme is 'http':

    if (Request::secure()) { 'Requested over HTTPS.'; }

Use ``method`` to retrieve the method of the HTTP request (e.g. GET, POST). The result is always returned in uppercase:

    $method = Request::method();

If implementing a REST API, use the ``safe`` method to determine if the request was "read only" (i.e. GET or HEAD).

Use the ``ajax`` method to determine if the request was submitted via XMLHttpRequest:

    if (Request::ajax()) { 'An AJAX request.'; }

The ``referrer`` method returns the address of the request's referrer. A default value can be returned should the referrer be undefined.

The ``entrusted`` method returns TRUE if all proxy servers are implicitly trusted (i.e. no trusted proxy servers are defined), or the request has passed through a specifically trusted proxy. See below for further detail on defining trusted proxy servers.

### Working with URLs
Use the ``url`` method to return the complete URL of the request and ``uri`` to return the URL path excluding the query string. The URI will always be returned with a '/' prefix.

    // Requested: http://a.com/blog/?id=1
    // Returned:  http://a.com/blog/?id=1
    $url = Request::url();

    // Returned: /blog
    $uri = Request::uri(); 

The URI is determined by inspection of the following headers: PATH_INFO, REQUEST_URI, PHP_SELF and REDIRECT_URL. It is possible to extend, or override the use of these headers by specifying custom URI resolvers. This is achieved by calling the ``resolvers`` method with an array of alternate headers, each with optional modifier functions for tweaking the returned value. The modifier should return FALSE if the URI cannot (or should not) be resolved from the header; any other value returned by the modifier function will be taken as the URI.

    // Add X_REWRITE_URI as a source for the URI, but only
    // if Windows is the server platform:
    Request::resolvers(array('X_REWRITE_URI' => function($uri) {
      return stripos(PHP_OS, 'WIN') ? $uri : FALSE;
    }));

Use the ``query`` method to return the query string of the request. Call the method with TRUE to include the '?' prefix.

    // Requested: http://a.com/blog/?name=joe&id=1
    // Returned:  name=joe&id=1
    $query = Request::query();

The ``segments`` method returns an array containing all URI segments. An optional array can be provided as a default value should the URI be empty.

    // Requested: http://a.com/blog/admin/posts/
    // Returned:  array('blog', 'admin', 'posts');
    $segments = Request::segments();

An individual URI segment can be retrieved using the ``segment`` method. The method takes a one-based index and an optional second parameter for the default value. Calling ``segment`` with a negative index evaluates segments in reverse order.

    // Requested: http://a.com/blog/admin/posts/
    // Returned:  blog
    $first = Request::segment(1);

    // Returned:  posts
    $last = Request::segment(-1);

### Client Properties
The ``languages`` method returns an array containing the languages accepted by a client. The languages are sorted in order of preference (highest preference first).

    // e.g. array('en-US', 'en');
    $languages = Request::languages();

The preferred language can be retrieved using the ``language`` method, which also accepts an optional default value.

The ``accepts`` method returns an array containing a preferentially ordered list of accepted media types (e.g. 'text/html'), and the ``accept`` method returns the media type with the highest preference.

By default the ``accept`` method returns the media type in a "friendly" format (e.g. 'html' or 'json'), but if called with an optional second argument of TRUE, the full media type will be returned.

    // Requested: http://a.com/code.js
    // Returned:  js
    // Default:   html
    $accepted = Request::accept('html');

    // Returned:  application/javascript
    $accepted = Request::accept('text/html', FALSE);

The Request class can seamlessly translate most of the common media types into a "friendly" format, but you can add support for additional format translations by using the ``format`` method. The first argument is the friendly format, and the second is the media type:

    // Support a new media type format:
    Request::format('font', array('application/x-font-woff',
      'application/font-off'));

The ``type`` method returns the content type of the body of a request. As with the ``accepts`` method, two optional arguments are supported; the first sets a default value, and the second controls the format of the result.

The ``charsets`` method returns an array containing a preferentially ordered list of accepted character sets (e.g. 'utf-8'), and the ``charset`` method returns the character set with the highest preference.

As with the ``language`` and ``accept`` methods, ``charset`` supports an optional default value.

The ``agent`` method returns the client user agent as a string (e.g. Mozilla/5.0 (Macintosh; …)).

The ``ip`` method seeks to return the IP address of the client. The returned value is influenced by factors including whether the value of the HTTP_CLIENT_IP header variable is trusted, and whether the request has been made via a trusted proxy server.

By default, both the client, and all proxy servers are trusted. If you do not trust the client, call the method with a value of FALSE:

    // Do not retrieve the IP address from HTTP_CLIENT_IP:
    $ip = Request::ip(FALSE);

To only trust an IP address relayed via specific proxy servers, you must first call the ``proxies`` method, passing an array containing the IP addresses of the trusted proxy servers:

    // Only trust IP addresses relayed via the proxy 10.0.0.10:
    Request::proxies('10.0.0.10');

    // To trust 10.0.0.10 and 10.0.0.11:
    Request::proxies(array('10.0.0.10', '10.0.0.11'));
