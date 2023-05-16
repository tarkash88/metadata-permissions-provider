# metadata-permissions-provider
This repository has the skeleton code to create custom metadata permissions provider in AEM

We mainly need to update the below files, this should suffice most of the business scenarios :
AssetMetadataAuthorizationConfiguration.java
AssetMetadataPermissionProvider.java

# Please note: 
- In the com.poc.dam.core.permissions.AssetMetadataAuthorizationConfiguration.cfg.json we can configure the comma seperated list of users that are to be considered as admin. 
- For this solution to work we need to apply deny read ACLs for "everyone" group, hence even for admin users it is expected that they are granted explicit access over required paths for the same to work. 
- Do not add looping logic in AssetMetadataPermissionProvider code as this will be trigerred at OAK level for each request. 