package it.zucchetti.filter;

import java.net.URISyntaxException;
import java.net.URI;
import java.util.Set;
import java.util.Iterator;
import java.util.List;
import java.util.LinkedList;
import org.apache.catalina.filters.CorsFilter;
import javax.servlet.FilterConfig;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.FilterChain;
import javax.servlet.ServletResponse;
import javax.servlet.ServletRequest;
import java.util.HashSet;
import org.apache.juli.logging.LogFactory;
import java.util.Collection;
import org.apache.tomcat.util.res.StringManager;
import org.apache.juli.logging.Log;
import javax.servlet.Filter;

public final class CustomCorsFilter implements Filter
{
    private static final Log log;
    private static final StringManager sm;
    private final Collection<String> allowedOrigins;
    private boolean anyOriginAllowed;
    private final Collection<String> allowedHttpMethods;
    private final Collection<String> allowedHttpHeaders;
    private final Collection<String> exposedHeaders;
    private boolean supportsCredentials;
    private long preflightMaxAge;
    private boolean decorateRequest;
    
    static {
        log = LogFactory.getLog((Class)CustomCorsFilter.class);
        sm = StringManager.getManager("org.apache.catalina.filters");
    }
    
    public CustomCorsFilter() {
        this.allowedOrigins = new HashSet<String>();
        this.allowedHttpMethods = new HashSet<String>();
        this.allowedHttpHeaders = new HashSet<String>();
        this.exposedHeaders = new HashSet<String>();
    }
    
    public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse, final FilterChain filterChain) throws IOException, ServletException {
        if (servletRequest instanceof HttpServletRequest && servletResponse instanceof HttpServletResponse) {
            final HttpServletRequest request = (HttpServletRequest)servletRequest;
            final HttpServletResponse response = (HttpServletResponse)servletResponse;
            final CORSRequestType requestType = this.checkRequestType(request);
            if (this.decorateRequest) {
                decorateCORSProperties(request, requestType);
            }
            switch (requestType) {
                case SIMPLE: {
                    this.handleSimpleCORS(request, response, filterChain);
                    break;
                }
                case ACTUAL: {
                    this.handleSimpleCORS(request, response, filterChain);
                    break;
                }
                case PRE_FLIGHT: {
                    this.handlePreflightCORS(request, response, filterChain);
                    break;
                }
                case NOT_CORS: {
                    this.handleNonCORS(request, response, filterChain);
                    break;
                }
                default: {
                    this.handleInvalidCORS(request, response, filterChain);
                    break;
                }
            }
            return;
        }
        throw new ServletException(CustomCorsFilter.sm.getString("corsFilter.onlyHttp"));
    }
    
    public void init(final FilterConfig filterConfig) throws ServletException {
        this.parseAndStore("*", "GET,POST,HEAD,OPTIONS", "Origin,Accept,X-Requested-With,Content-Type,Access-Control-Request-Method,Access-Control-Request-Headers", "", "true", "1800", "true");
        if (filterConfig != null) {
            final String configAllowedOrigins = filterConfig.getInitParameter("cors.allowed.origins");
            final String configAllowedHttpMethods = filterConfig.getInitParameter("cors.allowed.methods");
            final String configAllowedHttpHeaders = filterConfig.getInitParameter("cors.allowed.headers");
            final String configExposedHeaders = filterConfig.getInitParameter("cors.exposed.headers");
            final String configSupportsCredentials = filterConfig.getInitParameter("cors.support.credentials");
            final String configPreflightMaxAge = filterConfig.getInitParameter("cors.preflight.maxage");
            final String configDecorateRequest = filterConfig.getInitParameter("cors.request.decorate");
            this.parseAndStore(configAllowedOrigins, configAllowedHttpMethods, configAllowedHttpHeaders, configExposedHeaders, configSupportsCredentials, configPreflightMaxAge, configDecorateRequest);
        }
    }
    
    protected void handleSimpleCORS(final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain) throws IOException, ServletException {
        final CORSRequestType requestType = this.checkRequestType(request);
        if (requestType != CORSRequestType.SIMPLE && requestType != CORSRequestType.ACTUAL) {
            throw new IllegalArgumentException(CustomCorsFilter.sm.getString("corsFilter.wrongType2", new Object[] { CORSRequestType.SIMPLE, CORSRequestType.ACTUAL }));
        }
        final String origin = request.getHeader("Origin");
        final String method = request.getMethod();
        if (!this.isOriginAllowed(origin)) {
            this.handleInvalidCORS(request, response, filterChain);
        }
        else if (!this.allowedHttpMethods.contains(method)) {
            this.handleInvalidCORS(request, response, filterChain);
        }
        else {
            if (this.anyOriginAllowed && !this.supportsCredentials) {
                response.addHeader("Access-Control-Allow-Origin", "*");
            }
            else {
                response.addHeader("Access-Control-Allow-Origin", origin);
            }
            if (this.supportsCredentials) {
                response.addHeader("Access-Control-Allow-Credentials", "true");
            }
            if (this.exposedHeaders != null && this.exposedHeaders.size() > 0) {
                final String exposedHeadersString = join(this.exposedHeaders, ",");
                response.addHeader("Access-Control-Expose-Headers", exposedHeadersString);
            }
            filterChain.doFilter((ServletRequest)request, (ServletResponse)response);
        }
    }
    
    protected void handlePreflightCORS(final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain) throws IOException, ServletException {
        final CORSRequestType requestType = this.checkRequestType(request);
        if (requestType != CORSRequestType.PRE_FLIGHT) {
            throw new IllegalArgumentException(CustomCorsFilter.sm.getString("corsFilter.wrongType1", new Object[] { CORSRequestType.PRE_FLIGHT.name().toLowerCase() }));
        }
        final String origin = request.getHeader("Origin");
        if (!this.isOriginAllowed(origin)) {
            this.handleInvalidCORS(request, response, filterChain);
        }
        else {
            String accessControlRequestMethod = request.getHeader("Access-Control-Request-Method");
            if (accessControlRequestMethod != null && CorsFilter.HTTP_METHODS.contains(accessControlRequestMethod.trim())) {
                accessControlRequestMethod = accessControlRequestMethod.trim();
                final String accessControlRequestHeadersHeader = request.getHeader("Access-Control-Request-Headers");
                final List<String> accessControlRequestHeaders = new LinkedList<String>();
                if (accessControlRequestHeadersHeader != null && !accessControlRequestHeadersHeader.trim().isEmpty()) {
                    final String[] arr;
                    final String[] headers = arr = accessControlRequestHeadersHeader.trim().split(",");
                    for (int len = headers.length, i = 0; i < len; ++i) {
                        final String header = arr[i];
                        accessControlRequestHeaders.add(header.trim().toLowerCase());
                    }
                }
                if (!this.allowedHttpMethods.contains(accessControlRequestMethod)) {
                    this.handleInvalidCORS(request, response, filterChain);
                }
                else {
                    if (!accessControlRequestHeaders.isEmpty()) {
                        for (final String header2 : accessControlRequestHeaders) {
                            if (!this.allowedHttpHeaders.contains(header2)) {
                                this.handleInvalidCORS(request, response, filterChain);
                                return;
                            }
                        }
                    }
                    if (this.supportsCredentials) {
                        response.addHeader("Access-Control-Allow-Origin", origin);
                        response.addHeader("Access-Control-Allow-Credentials", "true");
                    }
                    else if (this.anyOriginAllowed) {
                        response.addHeader("Access-Control-Allow-Origin", "*");
                    }
                    else {
                        response.addHeader("Access-Control-Allow-Origin", origin);
                    }
                    if (this.preflightMaxAge > 0L) {
                        response.addHeader("Access-Control-Max-Age", String.valueOf(this.preflightMaxAge));
                    }
                    response.addHeader("Access-Control-Allow-Methods", accessControlRequestMethod);
                    if (this.allowedHttpHeaders != null && !this.allowedHttpHeaders.isEmpty()) {
                        response.addHeader("Access-Control-Allow-Headers", join(this.allowedHttpHeaders, ","));
                    }
                }
            }
            else {
                this.handleInvalidCORS(request, response, filterChain);
            }
        }
    }
    
    private void handleNonCORS(final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain) throws IOException, ServletException {
        filterChain.doFilter((ServletRequest)request, (ServletResponse)response);
    }
    
    private void handleInvalidCORS(final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain) {
        final String origin = request.getHeader("Origin");
        final String method = request.getMethod();
        final String accessControlRequestHeaders = request.getHeader("Access-Control-Request-Headers");
        response.setContentType("text/plain");
        response.setStatus(403);
        response.resetBuffer();
        if (CustomCorsFilter.log.isDebugEnabled()) {
            final StringBuilder message = new StringBuilder("Invalid CORS request; Origin=");
            message.append(origin);
            message.append(";Method=");
            message.append(method);
            if (accessControlRequestHeaders != null) {
                message.append(";Access-Control-Request-Headers=");
                message.append(accessControlRequestHeaders);
            }
            CustomCorsFilter.log.debug((Object)message.toString());
        }
    }
    
    public void destroy() {
    }
    
    protected static void decorateCORSProperties(final HttpServletRequest request, final CORSRequestType corsRequestType) {
        if (request == null) {
            throw new IllegalArgumentException(CustomCorsFilter.sm.getString("corsFilter.nullRequest"));
        }
        if (corsRequestType == null) {
            throw new IllegalArgumentException(CustomCorsFilter.sm.getString("corsFilter.nullRequestType"));
        }
        switch (corsRequestType) {
            case SIMPLE: {
                request.setAttribute("cors.isCorsRequest", (Object)Boolean.TRUE);
                request.setAttribute("cors.request.origin", (Object)request.getHeader("Origin"));
                request.setAttribute("cors.request.type", (Object)corsRequestType.name().toLowerCase());
                break;
            }
            case ACTUAL: {
                request.setAttribute("cors.isCorsRequest", (Object)Boolean.TRUE);
                request.setAttribute("cors.request.origin", (Object)request.getHeader("Origin"));
                request.setAttribute("cors.request.type", (Object)corsRequestType.name().toLowerCase());
                break;
            }
            case PRE_FLIGHT: {
                request.setAttribute("cors.isCorsRequest", (Object)Boolean.TRUE);
                request.setAttribute("cors.request.origin", (Object)request.getHeader("Origin"));
                request.setAttribute("cors.request.type", (Object)corsRequestType.name().toLowerCase());
                String headers = request.getHeader("Access-Control-Request-Headers");
                if (headers == null) {
                    headers = "";
                }
                request.setAttribute("cors.request.headers", (Object)headers);
                break;
            }
            case NOT_CORS: {
                request.setAttribute("cors.isCorsRequest", (Object)Boolean.FALSE);
                break;
            }
        }
    }
    
    protected static String join(final Collection<String> elements, final String joinSeparator) {
        String separator = ",";
        if (elements == null) {
            return null;
        }
        if (joinSeparator != null) {
            separator = joinSeparator;
        }
        final StringBuilder buffer = new StringBuilder();
        boolean isFirst = true;
        for (final String element : elements) {
            if (!isFirst) {
                buffer.append(separator);
            }
            else {
                isFirst = false;
            }
            if (element != null) {
                buffer.append(element);
            }
        }
        return buffer.toString();
    }
    
    protected CORSRequestType checkRequestType(final HttpServletRequest request) {
        CORSRequestType requestType = CORSRequestType.INVALID_CORS;
        if (request == null) {
            throw new IllegalArgumentException(CustomCorsFilter.sm.getString("corsFilter.nullRequest"));
        }
        final String originHeader = request.getHeader("Origin");
        if (originHeader != null) {
            if (originHeader.isEmpty()) {
                requestType = CORSRequestType.INVALID_CORS;
            }
            else if (!this.isValidOrigin(originHeader)) {
                requestType = CORSRequestType.INVALID_CORS;
            }
            else {
                final String method = request.getMethod();
                if (method != null && CorsFilter.HTTP_METHODS.contains(method)) {
                    if ("OPTIONS".equals(method)) {
                        final String contentType = request.getHeader("Access-Control-Request-Method");
                        if (contentType != null && !contentType.isEmpty()) {
                            requestType = CORSRequestType.PRE_FLIGHT;
                        }
                        else if (contentType != null && contentType.isEmpty()) {
                            requestType = CORSRequestType.INVALID_CORS;
                        }
                        else {
                            requestType = CORSRequestType.ACTUAL;
                        }
                    }
                    else if (!"GET".equals(method) && !"HEAD".equals(method)) {
                        if ("POST".equals(method)) {
                            String contentType = request.getContentType();
                            if (contentType != null) {
                                contentType = contentType.toLowerCase().trim();
                                if (CorsFilter.SIMPLE_HTTP_REQUEST_CONTENT_TYPE_VALUES.contains(contentType)) {
                                    requestType = CORSRequestType.SIMPLE;
                                }
                                else {
                                    requestType = CORSRequestType.ACTUAL;
                                }
                            }
                        }
                        else if (CorsFilter.COMPLEX_HTTP_METHODS.contains(method)) {
                            requestType = CORSRequestType.ACTUAL;
                        }
                    }
                    else {
                        requestType = CORSRequestType.SIMPLE;
                    }
                }
            }
        }
        else {
            requestType = CORSRequestType.NOT_CORS;
        }
        return requestType;
    }
    
    private boolean isOriginAllowed(final String origin) {
        return this.anyOriginAllowed || this.allowedOrigins.contains(origin);
    }
    
    private void parseAndStore(final String allowedOrigins, final String allowedHttpMethods, final String allowedHttpHeaders, final String exposedHeaders, final String supportsCredentials, final String preflightMaxAge, final String decorateRequest) throws ServletException {
        if (allowedOrigins != null) {
            if (allowedOrigins.trim().equals("*")) {
                this.anyOriginAllowed = true;
            }
            else {
                this.anyOriginAllowed = false;
                final Set<String> setExposedHeaders = this.parseStringToSet(allowedOrigins);
                this.allowedOrigins.clear();
                this.allowedOrigins.addAll(setExposedHeaders);
            }
        }
        if (allowedHttpMethods != null) {
            final Set<String> setExposedHeaders = this.parseStringToSet(allowedHttpMethods);
            this.allowedHttpMethods.clear();
            this.allowedHttpMethods.addAll(setExposedHeaders);
        }
        if (allowedHttpHeaders != null) {
            final Set<String> setExposedHeaders = this.parseStringToSet(allowedHttpHeaders);
            final Set<String> lowerCaseHeaders = new HashSet<String>();
            for (final String header : setExposedHeaders) {
                final String lowerCase = header.toLowerCase();
                lowerCaseHeaders.add(lowerCase);
            }
            this.allowedHttpHeaders.clear();
            this.allowedHttpHeaders.addAll(lowerCaseHeaders);
        }
        if (exposedHeaders != null) {
            final Set<String> setExposedHeaders = this.parseStringToSet(exposedHeaders);
            this.exposedHeaders.clear();
            this.exposedHeaders.addAll(setExposedHeaders);
        }
        if (supportsCredentials != null) {
            this.supportsCredentials = Boolean.parseBoolean(supportsCredentials);
        }
        if (preflightMaxAge != null) {
            try {
                if (!preflightMaxAge.isEmpty()) {
                    this.preflightMaxAge = Long.parseLong(preflightMaxAge);
                }
                else {
                    this.preflightMaxAge = 0L;
                }
            }
            catch (NumberFormatException var13) {
                throw new ServletException(CustomCorsFilter.sm.getString("corsFilter.invalidPreflightMaxAge"), (Throwable)var13);
            }
        }
        if (decorateRequest != null) {
            this.decorateRequest = Boolean.parseBoolean(decorateRequest);
        }
    }
    
    private Set<String> parseStringToSet(final String data) {
        String[] splits;
        if (data != null && data.length() > 0) {
            splits = data.split(",");
        }
        else {
            splits = new String[0];
        }
        final Set<String> set = new HashSet<String>();
        if (splits.length > 0) {
            final String[] arr = splits;
            for (int len = splits.length, i = 0; i < len; ++i) {
                final String split = arr[i];
                set.add(split.trim());
            }
        }
        return set;
    }
    
    protected boolean isValidOrigin(final String origin) {
        if (this.isAnyOriginAllowed()) {
            return true;
        }
        if (origin.contains("%")) {
            return false;
        }
        URI originURI;
        try {
            originURI = new URI(origin);
        }
        catch (URISyntaxException var3) {
            return false;
        }
        return originURI.getScheme() != null;
    }
    
    public boolean isAnyOriginAllowed() {
        return this.anyOriginAllowed;
    }
    
    public Collection<String> getExposedHeaders() {
        return this.exposedHeaders;
    }
    
    public boolean isSupportsCredentials() {
        return this.supportsCredentials;
    }
    
    public long getPreflightMaxAge() {
        return this.preflightMaxAge;
    }
    
    public Collection<String> getAllowedOrigins() {
        return this.allowedOrigins;
    }
    
    public Collection<String> getAllowedHttpMethods() {
        return this.allowedHttpMethods;
    }
    
    public Collection<String> getAllowedHttpHeaders() {
        return this.allowedHttpHeaders;
    }
    
    protected enum CORSRequestType
    {
        SIMPLE("SIMPLE", 0), 
        ACTUAL("ACTUAL", 1), 
        PRE_FLIGHT("PRE_FLIGHT", 2), 
        NOT_CORS("NOT_CORS", 3), 
        INVALID_CORS("INVALID_CORS", 4);
        
        private CORSRequestType(final String name, final int ordinal) {
        }
    }
}
