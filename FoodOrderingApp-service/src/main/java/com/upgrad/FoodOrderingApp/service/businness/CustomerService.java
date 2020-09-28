package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.CustomerDao;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthTokenEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthenticationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import com.upgrad.FoodOrderingApp.service.exception.UpdateCustomerException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;
import java.util.UUID;
import java.util.regex.Pattern;

@Service
public class CustomerService {

    @Autowired
    private CustomerDao customerDao;

    @Autowired
    private PasswordCryptographyProvider cryptographyProvider;

    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerEntity signUp(final CustomerEntity customerEntity) throws SignUpRestrictedException {

        if (checkExistingContactNumber(customerEntity.getContactNum())) {
            throw new SignUpRestrictedException("SGR-001", "This contact number is already registered! Try other contact number.");
        }

        if (checkEmptyFields(customerEntity)){
            throw new SignUpRestrictedException("SGR-005", "Except last name all fields should be filled");
        }

        if (!checkEmailAddress(customerEntity.getEmail())) {
            throw new SignUpRestrictedException("SGR-002", "Invalid email-id format!");
        }

        if (!checkContactNumber(customerEntity.getContactNum())) {
            throw new SignUpRestrictedException("SGR-003", "Invalid contact number!");
        }

        if(customerEntity.getPassword().length() < 8
                || !customerEntity.getPassword().matches(".*[0-9]+.*")
                || !customerEntity.getPassword().matches(".*[A-Z]+.*")
                || !customerEntity.getPassword().matches(".*[#@$%&*!^]+.*")){
            throw new SignUpRestrictedException("SGR-004", "Weak password!");
        }

        final String password = customerEntity.getPassword();

        final String[] encryptedText = cryptographyProvider.encrypt(password);

        customerEntity.setSalt(encryptedText[0]);
        customerEntity.setPassword(encryptedText[1]);

        return customerDao.signUp(customerEntity);
    }

    public boolean checkExistingContactNumber(final String contactNumber) {
        return customerDao.customerByContactNumber(contactNumber) != null;
    }

    public boolean checkEmailAddress(final String email) {
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\." +
                "[a-zA-Z0-9_+&*-]+)*@" +
                "(?:[a-zA-Z0-9-]+\\.)+[a-z" +
                "A-Z]{2,7}$";
        Pattern pat = Pattern.compile(emailRegex);

        if (email == null)
            return false;
        return pat.matcher(email).matches();
    }

    public boolean checkContactNumber(String contactNum) {
        String regex = "\\d{10}";
        Pattern pat = Pattern.compile(regex);

        if (contactNum == null)
            return false;
        return pat.matcher(contactNum).matches();
    }

    public boolean checkPassword(String password) {
        String PASSWORD_PATTERN = "((?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&]).{3,})";
        boolean flag = false;
        Pattern pattern = Pattern.compile(PASSWORD_PATTERN);
        if (password == null)
            return false;
        return pattern.matcher(password).matches();
    }

    public boolean checkEmptyFields(CustomerEntity customerEntity){

        if(customerEntity.getFirstName() == null || customerEntity.getEmail() == null ||
                customerEntity.getContactNum() == null || customerEntity.getPassword() == null)
            return true;
        return false;
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerAuthTokenEntity login(final String contactNumber, final String password) throws AuthenticationFailedException {

        final CustomerEntity customer = customerDao.customerByContactNumber(contactNumber);

        if (customer == null)
            throw new AuthenticationFailedException("ATH-001", "This contact number has not been registered!");

        final String encryptedPassword = PasswordCryptographyProvider.encrypt(password, customer.getSalt());

        if (encryptedPassword.equals(customer.getPassword())) {

            JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(encryptedPassword);
            CustomerAuthTokenEntity customerAuthTokenEntity = new CustomerAuthTokenEntity();
            customerAuthTokenEntity.setUuid(UUID.randomUUID().toString());
            customerAuthTokenEntity.setCustomer(customer);

            final ZonedDateTime now = ZonedDateTime.now();
            final ZonedDateTime expiresAt = now.plusHours(8);

            customerAuthTokenEntity.setAccessToken(jwtTokenProvider.generateToken(customer.getUuid(), now, expiresAt));
            customerAuthTokenEntity.setLoginAt(now);
            customerAuthTokenEntity.setExpiresAt(expiresAt);

            customerDao.createAuthToken(customerAuthTokenEntity);
            customerDao.updateCustomer(customer);

            return customerAuthTokenEntity;

        } else {
            throw new AuthenticationFailedException("ATH-002", "Invalid Credentials");
        }

    }

    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerAuthTokenEntity logout(final String authorizationToken) throws AuthorizationFailedException {

        final CustomerAuthTokenEntity customerAuthToken = customerDao.getCustomerAuthToken(authorizationToken);
        final ZonedDateTime now = ZonedDateTime.now();

        if(customerAuthToken == null){
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in.");
        }else if(customerAuthToken.getLogoutAt() != null){
            throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
        }else if(now.isAfter(customerAuthToken.getExpiresAt())){
            throw new AuthorizationFailedException("ATHR-002", "Your session is expired. Log in again to access this endpoint.");
        }

        customerAuthToken.setLogoutAt(now);
        customerDao.updateCustomerAuth(customerAuthToken);
        return customerAuthToken;
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerEntity updateCustomer(final String authorizationToken,final CustomerEntity updatedCustomerEntity) throws UpdateCustomerException, AuthorizationFailedException {

        final CustomerAuthTokenEntity customerAuthToken = customerDao.getCustomerAuthToken(authorizationToken);
        final ZonedDateTime now = ZonedDateTime.now();

        if(updatedCustomerEntity.getFirstName() == null){
            throw new UpdateCustomerException("UCR-002", "First name field should not be empty");
        }else if(customerAuthToken == null){
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in.");
        }else if(customerAuthToken.getLogoutAt() != null) {
            throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
        }else if(now.isAfter(customerAuthToken.getExpiresAt())){
            throw new AuthorizationFailedException("ATHR-002", "Your session is expired. Log in again to access this endpoint.");
        }

        final CustomerEntity customerEntity = customerAuthToken.getCustomer();

        customerEntity.setFirstName(updatedCustomerEntity.getFirstName());
        customerEntity.setLastName(updatedCustomerEntity.getLastName());

        customerDao.updateCustomer(customerEntity);
        return customerEntity;
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public CustomerEntity updatePassword(final String authorizationToken, final String oldPassword, final String newPassword) throws UpdateCustomerException, AuthorizationFailedException {

        final CustomerAuthTokenEntity customerAuthToken = customerDao.getCustomerAuthToken(authorizationToken);
        final ZonedDateTime now = ZonedDateTime.now();

        if(customerAuthToken == null){
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in.");
        }

        if(oldPassword == null || newPassword == null){
            throw new UpdateCustomerException("UCR-003", "No field should be empty");
        }else if(customerAuthToken.getLogoutAt() != null) {
            throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
        }else if(now.isAfter(customerAuthToken.getExpiresAt())){
            throw new AuthorizationFailedException("ATHR-002", "Your session is expired. Log in again to access this endpoint.");
        }else if (newPassword.length() < 8
                || !newPassword.matches(".*[0-9]+.*")
                || !newPassword.matches(".*[A-Z]+.*")
                || !newPassword.matches(".*[#@$%&*!^]+.*")) {
            throw new UpdateCustomerException("UCR-001", "Weak password!");
        }

        final CustomerEntity customerEntity = customerAuthToken.getCustomer();
        final String encryptedPassword = PasswordCryptographyProvider.encrypt(oldPassword,customerEntity.getSalt());

        if(!encryptedPassword.equals(customerEntity.getPassword())){
            throw new UpdateCustomerException("UCR-004", "Incorrect old password!");
        }

        customerEntity.setPassword(newPassword);
        final String password = customerEntity.getPassword();
        final String[] encryptedText = cryptographyProvider.encrypt(password);
        customerEntity.setSalt(encryptedText[0]);
        customerEntity.setPassword(encryptedText[1]);

        customerDao.updateCustomer(customerEntity);
        return customerEntity;
    }

}
