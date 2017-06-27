package org.apache.usergrid.security.providers;

import static org.apache.usergrid.persistence.Schema.PROPERTY_MODIFIED;
import static org.apache.usergrid.utils.ListUtils.anyNull;

import java.util.LinkedHashMap;
import java.util.Map;

import javax.ws.rs.core.MediaType;

import org.apache.usergrid.management.ManagementService;
import org.apache.usergrid.persistence.EntityManager;
import org.apache.usergrid.persistence.Query;
import org.apache.usergrid.persistence.Results;
import org.apache.usergrid.persistence.entities.User;
import org.apache.usergrid.persistence.index.query.Identifier;
import org.apache.usergrid.security.tokens.exceptions.BadTokenException;
import org.apache.usergrid.utils.JsonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provider implementation for sign-in-as with google
 *
 * @author amar
 */
public class GoogleProvider extends AbstractProvider {
    private static final String DEF_API_URL = "https://www.googleapis.com/oauth2/v2/userinfo";

    private Logger logger = LoggerFactory.getLogger( GoogleProvider.class );

    private String apiUrl = DEF_API_URL;


    GoogleProvider( EntityManager entityManager, ManagementService managementService ) {
        super( entityManager, managementService );
    }


    @Override
    void configure() {
        try {
            Map config = loadConfigurationFor( "googleProvider" );
            if ( config != null ) {
                String foundApiUrl = ( String ) config.get( "api_url" );
                if ( foundApiUrl != null ) {
                    apiUrl = foundApiUrl;
                }
            }
        }
        catch ( Exception ex ) {
            ex.printStackTrace();
        }
    }


    @Override
    public Map<Object, Object> loadConfigurationFor() {
        return loadConfigurationFor( "googleProvider" );
    }


    /** Configuration parameters we look for: <ul> <li>api_url</li> <li>pic_url</li> </ul> */
    @Override
    public void saveToConfiguration( Map<String, Object> config ) {
        saveToConfiguration( "googleProvider", config );
    }


    @Override
    Map<String, Object> userFromResource( String externalToken ) {
        return client.resource( apiUrl ).queryParam( "access_token", externalToken )
                     .accept( MediaType.APPLICATION_JSON ).get( Map.class );
    }


    @Override
    public User createOrAuthenticate( String externalToken ) throws BadTokenException {

        Map<String, Object> google_user = userFromResource( externalToken );

        String google_user_id = ( String ) google_user.get( "id" );
        String google_user_name = ( String ) google_user.get( "name" );
        String google_user_username = ( String ) google_user.get( "username" );
        String google_user_email = ( String ) google_user.get( "email" );
        String google_user_pic = ( String ) google_user.get( "picture" );
        if ( logger.isDebugEnabled() ) {
            logger.debug( JsonUtils.mapToFormattedJsonString( google_user ) );
        }

        User user = null;

        if ( ( google_user != null ) && !anyNull( google_user_id, google_user_name ) ) {

            Results r = null;
            try {
                final Query query = Query.fromEquals( "google.id",  google_user_id );
                r = entityManager.searchCollection( entityManager.getApplicationRef(), "users", query );
            }
            catch ( Exception ex ) {
                throw new BadTokenException( "Could not lookup user for that GOOGLE ID", ex );
            }
            if ( r.size() > 1 ) {
                logger.error( "Multiple users for GOOGLE ID: " + google_user_id );
                throw new BadTokenException( "multiple users with same Google ID" );
            }

            if ( r.size() < 1 ) {
                Map<String, Object> properties = new LinkedHashMap<String, Object>();

                properties.put( "google", google_user );
                properties.put( "username", "google_" + google_user_id );
                properties.put( "name", google_user_name );
                properties.put( "picture", google_user_pic );

                if ( google_user_email != null ) {
                    try {
                        user = managementService.getAppUserByIdentifier( entityManager.getApplication().getUuid(),
                                Identifier.fromEmail( google_user_email ) );
                    }
                    catch ( Exception ex ) {
                        throw new BadTokenException(
                                "Could not find existing user for this applicaiton for email: " + google_user_email, ex );
                    }
                    // if we found the user by email, unbind the properties from above
                    // that will conflict
                    // then update the user
                    if ( user != null ) {
                        properties.remove( "username" );
                        properties.remove( "name" );
                        try {
                            entityManager.updateProperties( user, properties );
                        }
                        catch ( Exception ex ) {
                            throw new BadTokenException( "Could not update user with new credentials", ex );
                        }
                        user.setProperty( PROPERTY_MODIFIED, properties.get( PROPERTY_MODIFIED ) );
                    }
                    else {
                        properties.put( "email", google_user_email );
                    }
                }
                if ( user == null ) {
                    properties.put( "activated", true );
                    try {
                        user = entityManager.create( "user", User.class, properties );
                    }
                    catch ( Exception ex ) {
                        throw new BadTokenException( "Could not create user for that token", ex );
                    }
                }
            }
            else {
                user = ( User ) r.getEntity().toTypedEntity();
                Map<String, Object> properties = new LinkedHashMap<String, Object>();

                properties.put( "google", google_user );
                properties.put( "picture", google_user_pic );
                try {
                    entityManager.updateProperties( user, properties );
                    user.setProperty( PROPERTY_MODIFIED, properties.get( PROPERTY_MODIFIED ) );
                    user.setProperty( "google", google_user );
                    user.setProperty( "picture", google_user_pic );
                }
                catch ( Exception ex ) {
                    throw new BadTokenException( "Could not update user properties", ex );
                }
            }
        }
        else {
            throw new BadTokenException( "Unable to confirm Google access token" );
        }

        return user;
    }
}
