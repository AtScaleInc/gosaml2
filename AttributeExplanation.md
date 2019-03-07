# How `<Attribute>` elements are represented converted to go structs 

The following XML will be converted to the structure below
```
<saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
  <saml:AttributeValue xsi:type="xs:string">auth0|5c79a3ca53f04526c2cc1e3a</saml:AttributeValue>
</saml:Attribute> 
```
```
map[
  http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier:{
    XMLName:{
      Space:urn:oasis:names:tc:SAML:2.0:assertion Local:Attribute
    } 
    FriendlyName: 
    Name:http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier 
    NameFormat:urn:oasis:names:tc:SAML:2.0:attrname-format:uri 
    Values:[
      {
        XMLName:{
          Space:urn:oasis:names:tc:SAML:2.0:assertion Local:AttributeValue
        } 
        Type: 
        Value: auth0|5c79a3ca53f04526c2cc1e3a
      }
    ]
  } 
]
```

With this in mind the way to access the 'real' values will be something like the code below:
```
for _, AttributeValue := range Values[Attribute.Name] {
  realValues := AttributeValue.Value
  // perhaps append to a list so all values for a particular attribute can be processed together
}
```