package be.i8c.wso2.esb;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.axis2.context.MessageContext;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Iterator;

import javax.xml.namespace.QName;

import com.nimbusds.jwt.JWTClaimsSet;

import be.i8c.wso2.esb.JwtClaimMapping;

public class JwtClaimsMap {

	private Log log = LogFactory.getLog(getClass());

	private ArrayList<JwtClaimMapping> claimsMap;

	public JwtClaimsMap(OMElement configClaims) {
		log.debug("Loading claims map from config");
		claimsMap = new ArrayList<JwtClaimMapping>();

		Iterator<OMElement> i = configClaims.getChildElements();
		while (i.hasNext()) {
			OMElement mapElement = i.next();
			JwtClaimMapping mapping = new JwtClaimMapping();
			mapping.SourceClaim = Utils.GetElement("JwtClaim", mapElement).getText();
			mapping.TargetProperty = Utils.GetElement("ContextProperty", mapElement).getText();
			mapping.Required = Boolean.parseBoolean(Utils.GetElement("Required", mapElement).getText());
			OMElement dateValidationElement = Utils.GetElement("DateValidationSeconds", mapElement);
			if (dateValidationElement != null) {
				mapping.ValidateDate = true;
				mapping.DateValidationSecondsPast = Integer.parseInt(dateValidationElement.getAttributeValue(QName.valueOf("Past")));
				mapping.DateValidationSecondsFuture = Integer.parseInt(dateValidationElement.getAttributeValue(QName.valueOf("Future")));
			}
			claimsMap.add(mapping);
		}
		log.info("Loaded JwtAuthHandler Configuration");
	}

	public void MapClaims(org.apache.synapse.MessageContext messageContext, JWTClaimsSet claims) throws Exception {
		Iterator<JwtClaimMapping> Imapping = claimsMap.iterator();
		while (Imapping.hasNext()) {
			JwtClaimMapping mapping = Imapping.next();
			Object claim = claims.getClaim(mapping.SourceClaim);
			if (claim == null) {
				if (mapping.Required || mapping.ValidateDate) {
					throw new Exception("Required claim \"" + mapping.SourceClaim + "\" not present");
				}

			}

			if (mapping.ValidateDate) {
				LocalDateTime now = LocalDateTime.now();
				LocalDateTime past = now.minusSeconds(mapping.DateValidationSecondsPast);
				LocalDateTime future = now.plusSeconds(mapping.DateValidationSecondsFuture);
				
				LocalDateTime claimDateTime = LocalDateTime.ofInstant(((Date)claim).toInstant(), ZoneId.systemDefault());

				log.debug("Now:  " + now.toString());
				log.debug("Past: " + past.toString());
				log.debug("Future: " + future.toString());
				log.debug("Claim" + claimDateTime.toString());

				if (!(claimDateTime.isAfter(past) && claimDateTime.isBefore(future))) {
					throw new Exception("Claim \"" + mapping.SourceClaim + "\" is not within the necessary window");
				}
				
			  }

			  messageContext.setProperty(mapping.TargetProperty, claim);
		  }
	  }
}
