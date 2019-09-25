package be.i8c.wso2.esb;

public class JwtClaimMapping {
	public String SourceClaim;
	public String TargetProperty;
	public boolean Required;
	public boolean ValidateDate;
	public int DateValidationSecondsPast;
	public int DateValidationSecondsFuture;
}
