importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("BranchingHelper");

IDMappingExtUtils.traceString("Entry HowToFIDO Authentication Decision");

var result = false;

var branchMap = {};

var mechanisms = [];

[mechanisms, branchMap] = getMechanismsAndBranchMap();

var username = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:token:attribute", "username");

IDMappingExtUtils.traceString("Username from request: " + username);

var type = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "type");
IDMappingExtUtils.traceString("Type from request: " + type);
if (username != null && username != "") {
    IDMappingExtUtils.traceString("User is already authenticated. Authentication Skipped.");
    state.put("skipDecision", "true");
    result = true;
}
else if (type == "fido2") {
    IDMappingExtUtils.traceString("Browser has a FIDO credential, and user chose to use FIDO");
    state.put("decision", branchMap["urn:ibm:security:authentication:asf:mechanism:fido2"]);
    result = true;
} else if (type == "password") {
    IDMappingExtUtils.traceString("User chose to try Username/Password.");
    state.put("operation", "verify");
    state.put("decision", branchMap["urn:ibm:security:authentication:asf:mechanism:password"]);
    result = true;
}


success.setValue(result);
IDMappingExtUtils.traceString("Exiting HowToFIDO Authentication Decision");
