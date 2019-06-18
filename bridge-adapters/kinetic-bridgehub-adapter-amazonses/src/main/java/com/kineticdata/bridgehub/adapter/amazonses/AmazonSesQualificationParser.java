package com.kineticdata.bridgehub.adapter.amazonses;

import com.kineticdata.bridgehub.adapter.QualificationParser;

public class AmazonSesQualificationParser extends QualificationParser {
    public String encodeParameter(String name, String value) {
        return value;
    }
}
