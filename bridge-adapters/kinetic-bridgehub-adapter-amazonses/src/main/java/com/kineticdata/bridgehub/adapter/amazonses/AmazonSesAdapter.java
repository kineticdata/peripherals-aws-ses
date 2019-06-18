package com.kineticdata.bridgehub.adapter.amazonses;

import com.kineticdata.bridgehub.adapter.BridgeAdapter;
import com.kineticdata.bridgehub.adapter.BridgeError;
import com.kineticdata.bridgehub.adapter.BridgeRequest;
import com.kineticdata.bridgehub.adapter.BridgeUtils;
import com.kineticdata.bridgehub.adapter.Count;
import com.kineticdata.bridgehub.adapter.Record;
import com.kineticdata.bridgehub.adapter.RecordList;
import com.kineticdata.commons.v1.config.ConfigurableProperty;
import com.kineticdata.commons.v1.config.ConfigurablePropertyMap;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.*;
import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.XML;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.slf4j.LoggerFactory;


public class AmazonSesAdapter implements BridgeAdapter {
    /*----------------------------------------------------------------------------------------------
     * PROPERTIES
     *--------------------------------------------------------------------------------------------*/

    /** Defines the adapter display name */
    public static final String NAME = "Amazon SES Bridge";

    /** Defines the logger */
    protected static final org.slf4j.Logger logger = LoggerFactory.getLogger(AmazonSesAdapter.class);

    /** Adapter version constant. */
    public static String VERSION;
    /** Load the properties version from the version.properties file. */
    static {
        try {
            java.util.Properties properties = new java.util.Properties();
            properties.load(AmazonSesAdapter.class.getResourceAsStream("/"+AmazonSesAdapter.class.getName()+".version"));
            VERSION = properties.getProperty("version");
        } catch (IOException e) {
            logger.warn("Unable to load "+AmazonSesAdapter.class.getName()+" version properties.", e);
            VERSION = "Unknown";
        }
    }

    /** Defines the collection of property names for the adapter */
    public static class Properties {
        public static final String ACCESS_KEY = "Access Key";
        public static final String SECRET_KEY = "Secret Key";
        public static final String REGION = "Region";
    }

    private final ConfigurablePropertyMap properties = new ConfigurablePropertyMap(
        new ConfigurableProperty(Properties.ACCESS_KEY).setIsRequired(true),
        new ConfigurableProperty(Properties.SECRET_KEY).setIsRequired(true).setIsSensitive(true),
        new ConfigurableProperty(Properties.REGION).setIsRequired(true)
    );

    private String accessKey;
    private String secretKey;
    private String region;

    /*---------------------------------------------------------------------------------------------
     * SETUP METHODS
     *-------------------------------------------------------------------------------------------*/

    @Override
    public void initialize() throws BridgeError {
        this.accessKey = properties.getValue(Properties.ACCESS_KEY);
        this.secretKey = properties.getValue(Properties.SECRET_KEY);
        this.region = properties.getValue(Properties.REGION);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getVersion() {
        return VERSION;
    }

    @Override
    public void setProperties(Map<String,String> parameters) {
        properties.setValues(parameters);
    }

    @Override
    public ConfigurablePropertyMap getProperties() {
        return properties;
    }

    private static final Map<String,String> STR_ALIASES = new HashMap() {{
        put("Identities","ListIdentities");
        put("SendStatistics","GetSendStatistics");
        put("SendQuota","GetSendQuota");
        put("VerifiedEmailAddresses","ListVerifiedEmailAddresses");
    }};

    private static final Map<String,String> NON_STD_STR_MAPPINGS = new HashMap() {{
        put("DescribeActiveReceiptRuleSet","Rules");
        put("DescribeReceiptRule","Rule");
        put("DescribeReceiptRuleSet","Rules");
        put("GetSendQuota",null);
        put("GetSendStatistics","SendDataPoints");
        put("ListIdentityPolicies","PolicyNames");
    }};

    /*---------------------------------------------------------------------------------------------
     * IMPLEMENTATION METHODS
     *-------------------------------------------------------------------------------------------*/

    @Override
    public Count count(BridgeRequest request) throws BridgeError {
        RecordList recordList = search(request);

        return new Count(recordList.getRecords().size());
    }

    @Override
    public Record retrieve(BridgeRequest request) throws BridgeError {
        RecordList recordList = search(request);
        List<Record> records = recordList.getRecords();

        Record record;
        if (records.size() > 1) {
            throw new BridgeError("Multiple results matched an expected single match query");
        } else if (records.isEmpty()) {
            record = new Record(null);
        } else {
            if (request.getFields() == null || request.getFields().isEmpty()) {
                record = records.get(0);
            } else {
                Map<String,Object> recordObject = new LinkedHashMap<String,Object>();
                for (String field : request.getFields()) {
                    recordObject.put(field, records.get(0).getValue(field));
                }
                record = new Record(recordObject);
            }
        }

        return record;
    }

    @Override
    public RecordList search(BridgeRequest request) throws BridgeError {
        // Get the aliased structure if it exists
        String structure = STR_ALIASES.containsKey(request.getStructure())
                ? STR_ALIASES.get(request.getStructure())
                : request.getStructure();

        AmazonSesQualificationParser parser = new AmazonSesQualificationParser();
        String query = parser.parse(request.getQuery(),request.getParameters());

        // The headers that we want to add to the request
        List<String> headers = new ArrayList<String>();

        // Build the url to retrieve the ec2 data
        StringBuilder url = new StringBuilder();
        url.append("https://email.").append(this.region).append(".amazonaws.com");
        url.append("?Version=2010-12-01&Action=").append(structure);
        if (!query.isEmpty()) url.append("&").append(query);

        // Make the request using the built up url/headers and bridge properties
        HttpResponse response = request("GET",url.toString(),headers,this.region,"email","",this.accessKey,this.secretKey);
        String output;
        try {
            output = EntityUtils.toString(response.getEntity());
        } catch (IOException e) { throw new BridgeError(e); }

        // Parse through the returned XML to get the structure records
        JSONObject json = (JSONObject)JSONValue.parse(XML.toJSONObject(output).toString());
        if (json.containsKey("ErrorResponse")) throw new BridgeError("Invalid Structure: '"+request.getStructure()+"' is not a currently supported structure.");
        JSONObject structureResponse = (JSONObject)json.get(structure+"Response");
        JSONObject structureResult = (JSONObject)structureResponse.get(structure+"Result");
        String structureIdentifier = NON_STD_STR_MAPPINGS.containsKey(structure) ? NON_STD_STR_MAPPINGS.get(structure) : structure.replaceFirst("\\A(?:GetIdentity|ListReceipt|List|Get|Describe)","");
        Object structureObj = structureIdentifier == null ? structureResult : structureResult.get(structureIdentifier);

        // Parse through the returned records - also handling converting 0 records returned and
        // 1 record retured to a JSONArray from an empty string and JSONObject respectively.
        JSONArray resultArray;
        if (structureObj instanceof JSONArray) {
            resultArray = (JSONArray)structureObj;
        } else if (structureObj instanceof JSONObject) {
            resultArray = new JSONArray();
            resultArray.add(structureObj);
        } else {
            resultArray = new JSONArray();
        }

        List<Record> records = new ArrayList<Record>();
        for (Object o : resultArray) {
            JSONObject recordObj = (JSONObject)o;
            if (recordObj.keySet().size() == 1 && recordObj.containsKey("member")) {
                // If the only key returned is member, the records are actually all listened under the
                // member object. The logic here converts the object under each member key to a
                // record object.
                Object member = recordObj.get("member");
                if (member instanceof JSONObject) {
                    records.add(new Record(buildRecord((JSONObject)member)));
                } else if (member instanceof JSONArray) {
                    for (Object memberArray : (JSONArray)member) {
                        if (memberArray instanceof JSONObject) {
                            records.add(new Record(buildRecord((JSONObject)memberArray)));
                        } else {
                            Map<String,Object> memberObj = new HashMap<String,Object>();
                            memberObj.put("member",memberArray);
                            records.add(new Record(memberObj));
                        }
                    }
                } else {
                    // Anything other than an empty string create a new record object with member
                    // as the field and the object as the value
                    if (!"".equals(o)) {
                        Map<String,Object> memberObj = new HashMap<String,Object>();
                        memberObj.put("member",member);
                        records.add(new Record(memberObj));
                    }
                }
            } else {
                // If the member key isn't the only key returned, handle the response like a single record
                records.add(new Record(buildRecord((JSONObject)o)));
            }
        }

        // Define the fields - if not fields were passed, set they keySet of the a returned objects as
        // the field set
        List<String> fields = request.getFields();
        if ((fields == null || fields.isEmpty()) && !records.isEmpty()) fields = new ArrayList<String>(records.get(0).getRecord().keySet());

        // Filter and sort the records
        records = filterRecords(records,query);
        if (request.getMetadata("order") == null) {
            // name,type,desc assumes name ASC,type ASC,desc ASC
            Map<String,String> defaultOrder = new LinkedHashMap<String,String>();
            for (String field : fields) {
                defaultOrder.put(field, "ASC");
            }
            records = BridgeUtils.sortRecords(defaultOrder, records);
        } else {
            // Creates a map out of order metadata
            Map<String,String> orderParse = BridgeUtils.parseOrder(request.getMetadata("order"));
            records = BridgeUtils.sortRecords(orderParse, records);
        }

        // Define the metadata
        Map<String,String> metadata = new LinkedHashMap<String,String>();
        metadata.put("size",String.valueOf(records.size()));
        metadata.put("nextPageToken",null);

        // Returning the response
        return new RecordList(fields, records, metadata);
    }

    /*----------------------------------------------------------------------------------------------
     * HELPER METHODS
     *--------------------------------------------------------------------------------------------*/

    private static final List<String> LIST_FIELD_KEYWORDS = new ArrayList(Arrays.asList(new String[] {
        "Attributes","Tokens"
    }));

    private Map<String,Object> buildRecord(JSONObject json) throws BridgeError {
        // Return the json keys
        Map<String,Object> record = new LinkedHashMap<String,Object>();
        Set<String> keys = json.keySet();
        for (String key : keys) {
            Object keyObject = json.get(key);
            for (String keyword : LIST_FIELD_KEYWORDS) {
                if (key.contains(keyword) && !(keyObject instanceof JSONArray)) {
                    JSONArray jsonArray = new JSONArray();
                    if (keyObject != null && keyObject != "") {
                        jsonArray.add(keyObject);
                    }
                    keyObject = jsonArray;
                    break;
                }
            }
            if (!record.containsKey(key)) {
                if (keyObject instanceof JSONObject) {
                    record.put(key,buildRecord((JSONObject)keyObject));
                } else if (keyObject instanceof JSONArray) {
                    JSONArray jsonArray = (JSONArray)keyObject;
                    record.put(key, new JSONArray());
                    for (Object o : jsonArray) {
                        if (o instanceof JSONArray) {
                            logger.debug(JSONValue.toJSONString(json));
                            throw new BridgeError("Bridge currently does not support parsing of nested JSON Arrays (at key == '"+key+"').");
                        }
                        else if (o instanceof JSONObject) {
                            ((List)record.get(key)).add(buildRecord((JSONObject)o));
                        } else {
                            ((List)record.get(key)).add(o);
                        }
                    }
                } else {
                    record.put(key,keyObject);
                }
            }
        }
        return record;
    }

    private Pattern getPatternFromValue(String value) {
        // Escape regex characters from value
        String[] parts = value.split("(?<!\\\\)%");
        for (int i = 0; i<parts.length; i++) {
            if (!parts[i].isEmpty()) parts[i] = Pattern.quote(parts[i].replaceAll("\\\\%","%"));
        }
        String regex = StringUtils.join(parts,".*?");
        if (!value.isEmpty() && value.substring(value.length() - 1).equals("%")) regex += ".*?";
        return Pattern.compile("^"+regex+"$",Pattern.CASE_INSENSITIVE);
    }

    protected final List<Record> filterRecords(List<Record> records, String query) throws BridgeError {
        if (query == null || query.isEmpty()) return records;
        String[] queryParts = query.split("&");

        Map<String[],Object[]> queryMatchers = new HashMap<String[],Object[]>();
        // Iterate through the query parts and create all the possible matchers to check against
        // the user results
        for (String part : queryParts) {
            String[] split = part.split("=");
            String field = split[0].trim();
            String value = split.length > 1 ? split[1].trim() : "";

            Object[] matchers;
            // Find the field and appropriate values for the query matcher
            if (value.equals("true") || value.equals("false")) {
                matchers = new Object[] { getPatternFromValue(value), Boolean.valueOf(value) };
            } else if (value.equals("null")) {
                matchers = new Object[] { null, getPatternFromValue(value) };
            } else if (value.isEmpty()) {
                matchers = new Object[] { "" };
            } else {
                matchers = new Object[] { getPatternFromValue(value) };
            }
            queryMatchers.put(new String[] { field }, matchers);
        }

        // Start with a full list of records and then delete from the list when they don't match
        // a qualification. Will be left with a list of values that match all qualifications.
        List<Record> matchedRecords = records;
        for (Map.Entry<String[],Object[]> entry : queryMatchers.entrySet()) {
            List<Record> matchedRecordsEntry = new ArrayList<Record>();
            for (String field : entry.getKey()) {
                for (Record record : matchedRecords) {
                    // If the field being matched isn't a key on the record, add it to the matched
                    // record list automatically so we aren't trying to query against information
                    // that doesn't exist on the object
                    if (!record.getRecord().containsKey(field)) matchedRecordsEntry.add(record);
                    // Check if the object matches the field qualification if it hasn't already been
                    // successfully matched
                    if (!matchedRecordsEntry.contains(record)) {
                        // Get the value for the field
                        Object fieldValue = record.getValue(field);
                        // Check the possible value matchers against the field value
                        for (Object value : entry.getValue()) {
                            if (fieldValue == value || // Objects equal
                                fieldValue != null && value != null && (
                                    value.getClass() == Pattern.class && ((Pattern)value).matcher(fieldValue.toString()).matches() || // fieldValue != null && Pattern matches
                                    value.equals(fieldValue) // fieldValue != null && values equal
                                )
                            ) {
                                matchedRecordsEntry.add(record);
                                break;
                            }
                        }
                    }
                }
            }
            matchedRecords = matchedRecordsEntry;
        }

        return matchedRecords;
    }

    /**
     * This method builds and sends a request to the Amazon EC2 REST API given the inputted
     * data and return a HttpResponse object after the call has returned. This method mainly helps with
     * creating a proper signature for the request (documentation on the Amazon REST API signing
     * process can be found here - http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html),
     * but it also throws and logs an error if a 401 or 403 is retrieved on the attempted call.
     *
     * @param url
     * @param headers
     * @param region
     * @param accessKey
     * @param secretKey
     * @return
     * @throws BridgeError
     */
    private HttpResponse request(String method, String url, List<String> headers, String region, String service, String payload, String accessKey, String secretKey) throws BridgeError {
        // Build a datetime timestamp of the current time (in UTC). This will be sent as a header
        // to Amazon and the datetime stamp must be within 5 minutes of the time on the
        // recieving server or else the request will be rejected as a 403 Forbidden
        DateFormat df = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        String datetime = df.format(new Date());
        String date = datetime.split("T")[0];

        // Create a URI from the request URL so that we can pull the host/path/query from it
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new BridgeError("There was an error parsing the inputted url '"+url+"' into a java URI.",e);
        }

        /* BUILD CANONCIAL REQUEST (uri, query, headers, signed headers, hashed payload)*/

        // Canonical URI (the part of the URL between the host and the ?. If blank, the uri is just /)
        String canonicalUri = uri.getPath().isEmpty() ? "/" : uri.getPath();

        // Canonical Query (parameter names sorted by asc and param names and values escaped
        // and trimmed)
        String canonicalQuery;
        // Trim the param names and values and load the parameters into a map
        Map<String,String> queryMap = new HashMap<String,String>();
        if (uri.getQuery() != null) {
            for (String parameter : uri.getQuery().split("&")) {
                queryMap.put(parameter.split("=")[0].trim(), parameter.split("=")[1].trim());
            }
        }

        StringBuilder queryBuilder = new StringBuilder();
        for (String key : new TreeSet<String>(queryMap.keySet())) {
            if (!queryBuilder.toString().isEmpty()) queryBuilder.append("&");
            queryBuilder.append(URLEncoder.encode(key)).append("=").append(URLEncoder.encode(queryMap.get(key)));
        }
        canonicalQuery = queryBuilder.toString();

        // Canonical Headers (lowercase and sort headers, add host and date headers if they aren't
        // already included, then create a header string with trimmed name and values and a new line
        // character after each header - including the last one)
        String canonicalHeaders;
        // Lowercase/trim each header and header value and load into a map
        Map<String,String> headerMap = new HashMap<String,String>();
        for (String header : headers) {
            headerMap.put(header.split(":")[0].toLowerCase().trim(), header.split(":")[1].trim());
        }
        // If the date and host headers aren't already in the header map, add them
        if (!headerMap.keySet().contains("host")) headerMap.put("host",uri.getHost());
        if (!headerMap.keySet().contains("x-amz-date")) headerMap.put("x-amz-date",datetime);
        // Sort the headers and append a newline to the end of each of them
        StringBuilder headerBuilder = new StringBuilder();
        for (String key : new TreeSet<String>(headerMap.keySet())) {
            headerBuilder.append(key).append(":").append(headerMap.get(key)).append("\n");
        }
        canonicalHeaders = headerBuilder.toString();

        // Signed Headers (a semicolon separated list of heads that were signed in the previous step)
        String signedHeaders = StringUtils.join(new TreeSet<String>(headerMap.keySet()),";");

        // Hashed Payload (a SHA256 hexdigest with the request payload - because the bridge only
        // does GET requests the payload will always be an empty string)
        String hashedPayload = DigestUtils.sha256Hex(payload);

        // Canonical Request (built out of 6 parts - the request method and the previous 5 steps in order
        // - with a newline in between each step and then a SHA256 hexdigest run on the resulting string)
        StringBuilder requestBuilder = new StringBuilder();
        requestBuilder.append(method).append("\n");
        requestBuilder.append(canonicalUri).append("\n");
        requestBuilder.append(canonicalQuery).append("\n");
        requestBuilder.append(canonicalHeaders).append("\n");
        requestBuilder.append(signedHeaders).append("\n");
        requestBuilder.append(hashedPayload);

        logger.debug(requestBuilder.toString());
        // Run the resulting string through a SHA256 hexdigest
        String canonicalRequest = DigestUtils.sha256Hex(requestBuilder.toString());

        /* BUILD STRING TO SIGN (credential scope, string to sign) */

        // Credential Scope (date, region, service, and terminating string [which is always aws4_request)
        String credentialScope = String.format("%s/%s/%s/aws4_request",date,region,service);

        // String to Sign (encryption method, datetime, credential scope, and canonical request)
        StringBuilder stringToSignBuilder = new StringBuilder();
        stringToSignBuilder.append("AWS4-HMAC-SHA256").append("\n");
        stringToSignBuilder.append(datetime).append("\n");
        stringToSignBuilder.append(credentialScope).append("\n");
        stringToSignBuilder.append(canonicalRequest);
        logger.debug(stringToSignBuilder.toString());
        String stringToSign = stringToSignBuilder.toString();

        /* CREATE THE SIGNATURE (signing key, signature) */

        // Signing Key
        byte[] signingKey;
        try {
            signingKey = getSignatureKey(secretKey,date,region,service);
        } catch (Exception e) {
            throw new BridgeError("There was a problem creating the signing key",e);
        }

        // Signature
        String signature;
        try {
            signature = Hex.encodeHexString(HmacSHA256(signingKey,stringToSign));
        } catch (Exception e) {
            throw new BridgeError("There was a problem creating the signature",e);
        }

        // Authorization Header (encryption method, access key, credential scope, signed headers, signature))
        String authorization = String.format("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",accessKey,credentialScope,signedHeaders,signature);

        /* CREATE THE HTTP REQUEST */
        HttpClient client = HttpClients.createDefault();
        HttpRequestBase request;
        try {
            if (method.toLowerCase().equals("get")) {
                request = new HttpGet(url);
            } else if (method.toLowerCase().equals("post")) {
                request = new HttpPost(url);
                ((HttpPost)request).setEntity(new StringEntity(payload));
            } else {
                throw new BridgeError("Http Method '"+method+"' is not supported");
            }
        } catch (UnsupportedEncodingException e) {
            throw new BridgeError(e);
        }

        request.setHeader("Authorization",authorization);
        for (Map.Entry<String,String> header : headerMap.entrySet()) {

            request.setHeader(header.getKey(),header.getValue());
        }

        HttpResponse response;
        try {
            response = client.execute(request);

            if (response.getStatusLine().getStatusCode() == 401 || response.getStatusLine().getStatusCode() == 403) {
                logger.error(EntityUtils.toString(response.getEntity()));
                throw new BridgeError("User not authorized to access this resource. Check the logs for more details.");
            }
        } catch (IOException e) { throw new BridgeError(e); }

        return response;
    }

    static byte[] HmacSHA256(byte[] key, String data) throws Exception {
        String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes("UTF8"));
    }

    static byte[] getSignatureKey(String secretKey, String date, String region, String service) throws Exception  {
         byte[] kSecret = ("AWS4" + secretKey).getBytes("UTF8");
         byte[] kDate    = HmacSHA256(kSecret, date);
         byte[] kRegion  = HmacSHA256(kDate, region);
         byte[] kService = HmacSHA256(kRegion, service);
         byte[] kSigning = HmacSHA256(kService, "aws4_request");
         return kSigning;
    }
}