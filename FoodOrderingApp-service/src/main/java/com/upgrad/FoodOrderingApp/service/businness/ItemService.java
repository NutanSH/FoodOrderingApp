package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.ItemDao;
import com.upgrad.FoodOrderingApp.service.dao.OrderDao;
import com.upgrad.FoodOrderingApp.service.dao.OrderItemDao;
import com.upgrad.FoodOrderingApp.service.entity.ItemEntity;
import com.upgrad.FoodOrderingApp.service.entity.OrderItemEntity;
import com.upgrad.FoodOrderingApp.service.entity.OrdersEntity;
import com.upgrad.FoodOrderingApp.service.entity.RestaurantEntity;
import com.upgrad.FoodOrderingApp.service.exception.ItemNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
public class ItemService {

    @Autowired
    private ItemDao itemDao;

    @Autowired
    private OrderDao orderDao;

    @Autowired
    private OrderItemDao orderItemDao;

    @Transactional(propagation = Propagation.REQUIRED)
    public ItemEntity getItemEntityById(final Integer itemId){
        return itemDao.getItemById(itemId);
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public ItemEntity getItemEntityByUuid(final String itemUuid) throws ItemNotFoundException {
        ItemEntity itemEntity = itemDao.getItemByUuid(itemUuid);
        if (itemEntity == null) {
            throw new ItemNotFoundException("INF-003", "No item by this id exist");
        } else {
            return itemEntity;
        }
    }

    @Transactional(propagation = Propagation.REQUIRED)
    public List<ItemEntity> getItemsByPopularity(RestaurantEntity restaurantEntity) {

        List<ItemEntity> itemEntityList = new ArrayList<>();

        for (OrdersEntity orderEntity : orderDao.getOrdersByRestaurant(restaurantEntity)) {
            for (OrderItemEntity orderItemEntity : orderItemDao.getItemsByOrder(orderEntity)) {
                itemEntityList.add(orderItemEntity.getItem());
            }
        }

        Map<String, Integer> map = new HashMap<String, Integer>();
        for (ItemEntity itemEntity : itemEntityList) {
            Integer count = map.get(itemEntity.getUuid());
            map.put(itemEntity.getUuid(), (count == null) ? 1 : count + 1);
        }

        Map<String, Integer> treeMap = new TreeMap<String, Integer>(map);
        List<ItemEntity> sortedItemEntityList = new ArrayList<ItemEntity>();
        for (Map.Entry<String, Integer> entry : treeMap.entrySet()) {
            sortedItemEntityList.add(itemDao.getItemByUuid(entry.getKey()));
        }

        Collections.reverse(sortedItemEntityList);

        return sortedItemEntityList;
    }

    public List<OrderItemEntity> getItemsByOrder(OrdersEntity orderEntity) {
        return orderItemDao.getItemsByOrder(orderEntity);
    }
}
