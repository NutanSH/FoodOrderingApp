package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.AddressDao;
import com.upgrad.FoodOrderingApp.service.dao.CustomerAddressDao;
import com.upgrad.FoodOrderingApp.service.dao.CustomerDao;
import com.upgrad.FoodOrderingApp.service.dao.StateDao;
import com.upgrad.FoodOrderingApp.service.entity.*;
import com.upgrad.FoodOrderingApp.service.exception.AddressNotFoundException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SaveAddressException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;
import java.util.List;

@Service
public class AddressService {

    @Autowired
    private CustomerDao customerDao;

    @Autowired
    private StateDao stateDao;

    @Autowired
    private AddressDao addressDao;

    @Autowired
    private CustomerAddressDao customerAddressDao;

    @Transactional(propagation = Propagation.REQUIRED)
    public StateEntity getStateByUUID(final String stateUuid) throws AddressNotFoundException {
        final StateEntity stateEntity = stateDao.getStateByUuid(stateUuid);
        if(stateEntity == null){
            throw new AddressNotFoundException("ANF-002", "No state by this id.");
        }
        return stateEntity;
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public StateEntity getStateById(Long stateId) {
        return stateDao.getStateById(stateId);
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public AddressEntity getAddressById(final Long addressId){
        return addressDao.getAddressById(addressId);
    }

    @Transactional
    public AddressEntity getAddressByUuid(final String addressUuid) {
        return addressDao.getAddressByUuid(addressUuid);
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public AddressEntity saveAddress(AddressEntity addressEntity, final String authorizationToken)
            throws AuthorizationFailedException, SaveAddressException, AddressNotFoundException {

        final CustomerAuthTokenEntity customerAuthToken = customerDao.getCustomerAuthToken(authorizationToken);
        final ZonedDateTime now = ZonedDateTime.now();

        if(customerAuthToken == null){
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in.");
        }else if(customerAuthToken.getLogoutAt() != null){
            throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
        }else if(now.isAfter(customerAuthToken.getExpiresAt())){
            throw new AuthorizationFailedException("ATHR-002", "Your session is expired. Log in again to access this endpoint.");
        }

        if (addressEntity.getCity() == null ||
                 addressEntity.getFlatBuildingNumber() == null ||
                 addressEntity.getLocality() ==null ||
                 addressEntity.getPincode() == null ||
                 addressEntity.getUuid() == null) {
            throw new SaveAddressException("SAR-001", "No field can be empty.");
        }else if (!addressEntity.getPincode().matches("[0-9]+") || addressEntity.getPincode().length() != 6) {
            throw new SaveAddressException("SAR-002", "Invalid pincode");
        }

        if(stateDao.getStateByUuid(addressEntity.getState().getUuid()) == null){
            throw new AddressNotFoundException("ANF-002", "No state by this id.");
        }

        addressEntity = addressDao.saveAddress(addressEntity);

        final CustomerEntity customerEntity = customerDao.getCustomerByUuid(customerAuthToken.getCustomer().getUuid());
        final CustomerAddressEntity customerAddressEntity = new CustomerAddressEntity();

        customerAddressEntity.setAddress(addressEntity);
        customerAddressEntity.setCustomer(customerEntity);
        customerAddressDao.createCustomerAddress(customerAddressEntity);

        return addressEntity;
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public List<AddressEntity> getAllSavedAddresses(final String authorizationToken) throws AuthorizationFailedException {

        final CustomerAuthTokenEntity customerAuthToken = customerDao.getCustomerAuthToken(authorizationToken);
        final ZonedDateTime now = ZonedDateTime.now();

        if(customerAuthToken == null){
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in.");
        }else if(customerAuthToken.getLogoutAt() != null){
            throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
        }else if(now.isAfter(customerAuthToken.getExpiresAt())){
            throw new AuthorizationFailedException("ATHR-002", "Your session is expired. Log in again to access this endpoint.");
        }

        return customerAddressDao.getAddressForCustomerByUuid(customerAuthToken.getCustomer().getUuid());
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public AddressEntity deleteSavedAddress(final String addressUuid, final String authorizationToken)
            throws AuthorizationFailedException, AddressNotFoundException {

        final CustomerAuthTokenEntity customerAuthToken = customerDao.getCustomerAuthToken(authorizationToken);
        final ZonedDateTime now = ZonedDateTime.now();

        if(customerAuthToken == null){
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in.");
        }else if(customerAuthToken.getLogoutAt() != null){
            throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
        }else if(now.isAfter(customerAuthToken.getExpiresAt())){
            throw new AuthorizationFailedException("ATHR-002", "Your session is expired. Log in again to access this endpoint.");
        }

        AddressEntity addressEntity = addressDao.getAddressByUuid(addressUuid);
        CustomerAddressEntity customerAddressEntity = customerAddressDao.getCustomerAddressByCustomerIdAddressId(customerAuthToken.getCustomer(), addressEntity);

        if (addressEntity == null) {
            throw new AddressNotFoundException("ANF-003", "No address by this id.");
        } else if (customerAddressEntity == null) {
            throw new AuthorizationFailedException("ATHR-004", "You are not authorized to view/update/delete any one else's address");
        }

        if (addressUuid == null) {
            throw new AddressNotFoundException("ANF-005", "Address id can not be empty.");
        }

        return addressDao.deleteAddress(addressEntity);
    }

    public List<StateEntity> getAllStates(){
        return stateDao.getAllStates();
    }

}
