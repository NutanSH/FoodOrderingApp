package com.upgrad.FoodOrderingApp.service.dao;

import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthTokenEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;

@Repository
public class CustomerDao {

    @PersistenceContext
    private EntityManager entityManager;

    public CustomerEntity customerSignUp(CustomerEntity customerEntity){
        entityManager.persist(customerEntity);
        return customerEntity;
    }

    public CustomerEntity customerByContactNumber(String contactNumber){
        try{
            return entityManager.createNamedQuery("customerByContactNumber",CustomerEntity.class)
                    .setParameter("contactNumber",contactNumber).getSingleResult();
        }catch (NoResultException nre){
            return null;
        }
    }

    public CustomerEntity getCustomerByUuid(final String uuid) {
        try {
            return entityManager.createNamedQuery("customerByUuid", CustomerEntity.class).setParameter("uuid", uuid)
                    .getSingleResult();
        } catch(NoResultException nre) {
            return null;
        }
    }

    public CustomerAuthTokenEntity createCustomerAuthToken(CustomerAuthTokenEntity customerAuthTokenEntity){
        entityManager.persist(customerAuthTokenEntity);
        return customerAuthTokenEntity;
    }

    public void updateCustomer(CustomerEntity customerEntity){
        entityManager.merge(customerEntity);
    }

    public CustomerAuthTokenEntity getCustomerAuthToken(String accessToken){
        try{
            return entityManager.createNamedQuery("customerAuthTokenByAccessToken",CustomerAuthTokenEntity.class)
                    .setParameter("accessToken",accessToken).getSingleResult();
        }catch(NoResultException nre){
            return null;
        }
    }

    public void updateCustomerAuthToken(CustomerAuthTokenEntity customerAuthTokenEntity){
        entityManager.merge(customerAuthTokenEntity);
    }

}
