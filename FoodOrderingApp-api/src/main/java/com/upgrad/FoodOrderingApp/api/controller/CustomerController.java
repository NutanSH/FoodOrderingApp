package com.upgrad.FoodOrderingApp.api.controller;

import com.upgrad.FoodOrderingApp.api.model.*;
import com.upgrad.FoodOrderingApp.service.businness.CustomerService;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthTokenEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthenticationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import com.upgrad.FoodOrderingApp.service.exception.UpdateCustomerException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@CrossOrigin
@RestController
@RequestMapping("/")
public class CustomerController {

    @Autowired
    private CustomerService customerBusinessService;

    @CrossOrigin
    @RequestMapping(method = RequestMethod.POST, path = "/customer/signup", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<SignupCustomerResponse> signUp(final SignupCustomerRequest signupCustomerRequest) throws SignUpRestrictedException {


        CustomerEntity customerEntity = new CustomerEntity();
        customerEntity.setUuid(UUID.randomUUID().toString());
        customerEntity.setFirstName(signupCustomerRequest.getFirstName());
        customerEntity.setLastName(signupCustomerRequest.getLastName());
        customerEntity.setContactNum(signupCustomerRequest.getContactNumber());
        customerEntity.setEmail(signupCustomerRequest.getEmailAddress());
        customerEntity.setPassword(signupCustomerRequest.getPassword());

        CustomerEntity customer = customerBusinessService.signUp(customerEntity);
        return new ResponseEntity<SignupCustomerResponse>(new SignupCustomerResponse().id(customer.getUuid()).status("CUSTOMER SUCCESSFULLY REGISTERED"), HttpStatus.CREATED);
    }

    @CrossOrigin
    @RequestMapping(method = RequestMethod.POST, path = "/customer/login", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<LoginResponse> login(@RequestHeader("authorization") final String authorization, HttpSession session) throws AuthenticationFailedException {

        final byte[] decode;
        try {
            decode = Base64.getDecoder().decode(authorization.split("Basic ")[1]);
        } catch(ArrayIndexOutOfBoundsException e) {
            throw new AuthenticationFailedException("ATH-003", "Incorrect format of decoded customer name and password");
        }
        String decodedText = new String(decode);
        if (!decodedText.matches("([0-9]+):(.+?)")) {
            throw new AuthenticationFailedException("ATH-003", "Incorrect format of decoded customer name and password");
        }
        final String[] decodedArray = decodedText.split(":");

        final CustomerAuthTokenEntity authTokenEntity = customerBusinessService.login(decodedArray[0], decodedArray[1]);
        final CustomerEntity customer = authTokenEntity.getCustomer();

        HttpHeaders httpHeaders = new HttpHeaders();
        List<String> header = new ArrayList<>();
        header.add("access-token");
        httpHeaders.add("access_token",authTokenEntity.getAccessToken());
        httpHeaders.setAccessControlExposeHeaders(header);

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setId(customer.getUuid());
        loginResponse.setFirstName(customer.getFirstName());
        loginResponse.setLastName(customer.getLastName());
        loginResponse.setEmailAddress(customer.getEmail());
        loginResponse.setContactNumber(customer.getContactNum());
        loginResponse.setMessage("LOGGED IN SUCCESSFULLY");

        return new ResponseEntity<LoginResponse>(loginResponse,httpHeaders,HttpStatus.OK);

    }

    @CrossOrigin
    @RequestMapping(method = RequestMethod.POST, path = "/customer/logout", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<LogoutResponse> logout(@RequestHeader("authorization") final String authorization) throws AuthorizationFailedException {

        String[] bearerToken = authorization.split( "Bearer ");
        final CustomerAuthTokenEntity customerAuthTokenEntity = customerBusinessService.logout(bearerToken[1]);
        final CustomerEntity customerEntity = customerAuthTokenEntity.getCustomer();

        return new ResponseEntity<LogoutResponse>
                (new LogoutResponse().id(customerEntity.getUuid()).message("LOGGED OUT SUCCESSFULLY"),HttpStatus.OK);
        }

    @RequestMapping(method = RequestMethod.PUT, path = "/customer",consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<UpdateCustomerResponse> updateCustomer(final UpdateCustomerRequest updateCustomerRequest,@RequestHeader("authorization") final String authorization) throws AuthorizationFailedException, UpdateCustomerException {

        final CustomerEntity updatedCustomerEntity = new CustomerEntity();
        updatedCustomerEntity.setFirstName(updateCustomerRequest.getFirstName());
        updatedCustomerEntity.setLastName(updateCustomerRequest.getLastName());

        String[] bearerToken = authorization.split( "Bearer ");

        final CustomerEntity customerEntity = customerBusinessService.updateCustomer(bearerToken[1], updatedCustomerEntity);

        UpdateCustomerResponse updateCustomerResponse = new UpdateCustomerResponse()
                .id(customerEntity.getUuid())
                .firstName(customerEntity.getFirstName())
                .lastName(customerEntity.getLastName())
                .status("“CUSTOMER DETAILS UPDATED SUCCESSFULLY”");

        return new ResponseEntity<UpdateCustomerResponse>(updateCustomerResponse,HttpStatus.OK);
    }

    @RequestMapping(method = RequestMethod.PUT, path = "/customer/password",consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<UpdatePasswordResponse> updateCustomerPassword(final UpdatePasswordRequest updatePasswordRequest,@RequestHeader("authorization") final String authorization) throws AuthorizationFailedException, UpdateCustomerException {

        String[] bearerToken = authorization.split( "Bearer ");
        final String oldPassword = updatePasswordRequest.getOldPassword();
        final String newPassword = updatePasswordRequest.getNewPassword();

        final CustomerEntity customerEntity = customerBusinessService.updatePassword(bearerToken[1], oldPassword, newPassword);

        return new ResponseEntity<UpdatePasswordResponse>
                (new UpdatePasswordResponse().id(customerEntity.getUuid()).status("CUSTOMER PASSWORD UPDATED SUCCESSFULLY"),HttpStatus.OK);
    }
}
