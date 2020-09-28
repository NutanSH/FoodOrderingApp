package com.upgrad.FoodOrderingApp.service.dao;

import com.upgrad.FoodOrderingApp.service.entity.AddressEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAddressEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;
import java.util.ArrayList;
import java.util.List;

@Repository
public class CustomerAddressDao {

    @PersistenceContext
    private EntityManager entityManager;

    public void createCustomerAddress(CustomerAddressEntity customerAddressEntity) {
        entityManager.persist(customerAddressEntity);
    }

    public List<AddressEntity> getAddressForCustomerByUuid(final String uuid) {
        try {
            CustomerEntity customerEntity = entityManager.createNamedQuery("customerByUuid", CustomerEntity.class)
                    .setParameter("uuid", uuid).getSingleResult();

            //getting all addresses linked to a particular customer
            List<CustomerAddressEntity> customerAddressEntities = entityManager
                    .createNamedQuery("customerAddressesListByCustomerId", CustomerAddressEntity.class)
                    .setParameter("customer", customerEntity).getResultList();

            if (customerAddressEntities.size() == 0) {
                return null;
            }

            List<Long> idList = new ArrayList<>();
            for (CustomerAddressEntity cae : customerAddressEntities) {
                idList.add(cae.getAddress().getId());
            }

            return entityManager
                    .createNamedQuery("getAllAddresses", AddressEntity.class)
                    .setParameter("addressIds", idList).getResultList();
        } catch (NoResultException nre) {
            return null;
        }
    }

    public CustomerAddressEntity getCustomerAddressByCustomerIdAddressId(final CustomerEntity customerEntity, final AddressEntity addressEntity) {
        try {
            return entityManager.createNamedQuery("customerAddressByCustomerIdAddressId", CustomerAddressEntity.class)
                    .setParameter("customer", customerEntity).setParameter( "address", addressEntity)
                    .getSingleResult();
        } catch(NoResultException nre) {
            return null;
        }
    }
}
