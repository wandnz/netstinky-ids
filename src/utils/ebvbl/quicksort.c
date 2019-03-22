#include "quicksort.h"

size_t
calcOffset (ELEMENT_SZ size, size_t numElements)
{
    return size * numElements;
}

ELEMENT_PTR
getElement (void *array, ELEMENT_SZ size, ELEMENT_INDEX i)
{
    assert(array != NULL);
    assert(size > 0);
    
    char *element = (char *)array + calcOffset(size, i);
    return (ELEMENT_PTR)element;
}

bool
quicksort (void *array, ELEMENT_SZ size, COMPARE_F_PTR compare,
           ELEMENT_INDEX lo, ELEMENT_INDEX hi)
{
    assert(array != NULL);
    assert(size > 0);
    assert(compare != NULL);
    
    bool result = true;
    
    if (lo < hi)
    {
        ELEMENT_INDEX p = partition(array, size, compare, lo, hi);
        
        // possible for sort to fail if swapping doesn't have enough memory
        if (p == -1 || !quicksort(array, size, compare, lo, p) ||
                       !quicksort(array, size, compare, p + 1, hi))
            result = false;
    }
    
    return result;
}

bool
swapElements (void *array, ELEMENT_SZ size, ELEMENT_INDEX a, ELEMENT_INDEX b)
{
    bool success = false;
    ELEMENT_PTR t = malloc(size);
    
    if (t != NULL)
    {
        ELEMENT_PTR aPtr = getElement(array, size, a);
        ELEMENT_PTR bPtr = getElement(array, size, b);
        memcpy(t, aPtr, size);
        memcpy(aPtr, bPtr, size);
        memcpy(bPtr, t, size);
        free(t);
        success = true;
    }
    
    return success;
}

ELEMENT_INDEX
partition(void *array, ELEMENT_SZ size, COMPARE_F_PTR compare, ELEMENT_INDEX lo,
          ELEMENT_INDEX hi)
{
    assert(array != NULL);
    assert(size > 0);
    
    void *pivotValue = malloc(size);
    memcpy(pivotValue, getElement(array, size, lo), size);
    
    ELEMENT_INDEX i, j;
    i = lo - 1;
    j = hi + 1;
    
    ELEMENT_INDEX result;
    
    // find out of order elements on each side of the pivot and swap them
    while (1)
    {
        do
        {
            i++;
        }
        while (compare(getElement(array, size, i), pivotValue) < 0);
        
        do
        {
            j--;
        }
        while (compare(getElement(array, size, j), pivotValue) > 0);
        
        if (i >= j)
        {
            result = j;
            break;
        } else
        {        
            ELEMENT_INDEX swapResult = swapElements(array, size, i, j);

            // check swap was successful
            if (swapResult == -1)
            {
                result = -1;
                break;
            }
        }
    }
    
    free(pivotValue);
    return result;
}