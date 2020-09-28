package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.CustomerDao;
import com.upgrad.FoodOrderingApp.service.dao.RestaurantDao;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthTokenEntity;
import com.upgrad.FoodOrderingApp.service.entity.RestaurantCategoryEntity;
import com.upgrad.FoodOrderingApp.service.entity.RestaurantEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.InvalidRatingException;
import com.upgrad.FoodOrderingApp.service.exception.RestaurantNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.text.DecimalFormat;
import java.time.ZonedDateTime;
import java.util.List;

@Service
public class RestaurantService {

    @Autowired
    private RestaurantDao restaurantDao;

    @Autowired
    private CustomerDao customerDao;

    @Transactional(propagation = Propagation.REQUIRED)
    public List<RestaurantEntity> getAllRestaurants() {
        return restaurantDao.getAllRestaurants();
    }

    public List<RestaurantEntity> getRestaurantsByName(String restaurantName) throws RestaurantNotFoundException {

        if(restaurantName == null){
            throw new RestaurantNotFoundException("RNF-003", "Restaurant name field should not be empty");
        }
        return restaurantDao.getRestaurantsByName(restaurantName);
    }

    public List<RestaurantCategoryEntity> getRestaurantByCategoryId(final Long categoryID) {
        return restaurantDao.getRestaurantByCategoryId(categoryID);
    }

    public RestaurantEntity getRestaurantByUUId(String restaurantUUID) {
        return restaurantDao.getRestaurantByUUId(restaurantUUID);
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public RestaurantEntity updateRestaurant (final Double customerRating, final String restaurantId, final String authorizationToken)
            throws AuthorizationFailedException, RestaurantNotFoundException, InvalidRatingException {

        final CustomerAuthTokenEntity customerAuthToken = customerDao.getCustomerAuthToken(authorizationToken);
        final ZonedDateTime now = ZonedDateTime.now();

        if(customerAuthToken == null){
            throw new AuthorizationFailedException("ATHR-001", "Customer is not Logged in.");
        }else if(customerAuthToken.getLogoutAt() != null){
            throw new AuthorizationFailedException("ATHR-002", "Customer is logged out. Log in again to access this endpoint.");
        }else if(now.isAfter(customerAuthToken.getExpiresAt())){
            throw new AuthorizationFailedException("ATHR-002", "Your session is expired. Log in again to access this endpoint.");
        }

        if(restaurantId == null){
            throw new RestaurantNotFoundException("RNF-002", "Restaurant id field should not be empty");
        }

        RestaurantEntity restaurantEntity =  restaurantDao.getRestaurantByUUId(restaurantId);

        if (restaurantEntity == null) {
            throw new RestaurantNotFoundException("RNF-001", "No restaurant by this id");
        }

        if(customerRating == null || customerRating.isNaN() || customerRating < 1 || customerRating > 5 ){
            throw new InvalidRatingException("IRE-001", "Restaurant should be in the range of 1 to 5");
        }

        DecimalFormat format = new DecimalFormat("##.0");
        double restaurantRating = restaurantEntity.getCustomerRating();
        Integer restaurantNoOfCustomerRated = restaurantEntity.getNumCustomersRated();
        double newCustomerRating = (restaurantRating*(restaurantNoOfCustomerRated.doubleValue())+customerRating)
                /restaurantEntity.getNumCustomersRated();
        restaurantEntity.setNumCustomersRated(restaurantNoOfCustomerRated+1);
        restaurantEntity.setCustomerRating(Double.parseDouble(format.format(newCustomerRating)));

        restaurantDao.updateRestaurant(restaurantEntity);
        return restaurantEntity;
    }

}
